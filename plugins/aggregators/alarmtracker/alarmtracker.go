package alarmtracker

import (
    "bytes"
    "hash/fnv"
    "io"
    "encoding/json"
	"net/http"
    "strings"
    "net/url"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/internal/tls"
	"github.com/influxdata/telegraf/plugins/aggregators"
)
const (
    sampleConfig = `
  ## General Aggregator Arguments:
  ## The period on which to flush & clear the aggregator.
  period = "30s"
  ## If true, the original metric will be dropped by the
  ## aggregator and will not get sent to the output plugins.
  drop_original = false

  ## Specific AlarmTracker Arguments:
  ## The tags that contain alarm event names
  alarm_tags = ["name"]
  ## The tags that supply the "GROUP BY" clause for initializing trap counts and
  ## are periodically output
  identifiers = ["host", "source"]

  ## List the alarms to be tracked by AlarmTracked in the "alarms" table. Format
  ## each entry as raised_oid = cleared_oid. For example,
  ##
  ## [aggregators.alarmtracker.alarms]
  ##   theAlarmWasRaised = theAlarmHasCleared
  ##
  ## If, the table is undefined, all values in the alarm_tags tags are treated
  ## as alarms. If the OID has the suffix "Clear", it is an alarm cleared event
  ## and an alarm raised event otherwise.
  ##
  ## The plugin resets all status to false if it receives any of the OIDs in
  ## the reset_on array.
  reset_on_values = ["startupNotification"]

  ## URL from which to read InfluxDB-formatted JSON
  ## Default is "http://localhost:8086/query".
  url = "http://localhost:8086/query"
  ## Database and measurement values used to build the LAST() query. The
  ## following values, in combination with the url and identifiers parameters above
  ## would build a final url: 
  ## http://localhost:8086/query?db=telegraf&q=SELECT LAST(*) FROM alarm GROUP BY host, source
  database = "telegraf"
  measurement = "alarm"

  ## Username and password to send using HTTP Basic Authentication.
  # username = ""
  # password = ""

  ## Optional TLS Config
  # tls_ca = "/etc/telegraf/ca.pem"
  # tls_cert = "/etc/telegraf/cert.pem"
  # tls_key = "/etc/telegraf/key.pem"
  ## Use TLS but skip chain & host verification
  # insecure_skip_verify = false

`
)

type Tracker struct {
	tags        map[string]string
	alarmStatus map[string]int

    plugin      *AlarmTracker
    updated     bool
}
type TrackerCache map[uint64]*Tracker

func (self *Tracker) Reset() {
    for alarm, status := range self.alarmStatus {
        if status != 0 {
            self.plugin.Log.Debugf("Reseting '%s'", alarm)
            self.alarmStatus[alarm] = 0
            self.updated = true
        }
    }
}

// Tracker.alarmStatus tracks whether an alarm is active by mapping the OID of a
// alarm status change notification to an integer representing a bool (1 or 0).
func (self *Tracker) SetAlarmStatus(oid string) {
    raised_oid := ""
    var ok, is_raised bool

    // Are alarm pair mappings in use?
    if self.plugin.RaiseToClear == nil {
        // No. Calculate raised_oid from presence/absence of "Clear" suffix
        if strings.HasSuffix(oid, "Clear") {
            self.plugin.Log.Debugf("OID '%s' has 'Clear' suffix", oid)
            raised_oid = strings.TrimSuffix(oid, "Clear")
            is_raised = false
        } else {
            self.plugin.Log.Debugf("OID '%s' is a raised event", oid)
            raised_oid = oid
            is_raised = true
        }

    } else {
        if raised_oid, ok = self.plugin.ClearToRaise[oid]; ok {
            self.plugin.Log.Debugf("OID '%s' found in ClearToRaise", oid)
            is_raised = false
        } else if _, ok = self.plugin.RaiseToClear[oid]; ok {
            self.plugin.Log.Debugf("OID '%s' found in RaiseToClear", oid)
            raised_oid = oid
            is_raised = true
        }
    }

    if raised_oid != "" {
        if (self.alarmStatus[raised_oid] != 0) != is_raised {
            if is_raised {
                self.alarmStatus[raised_oid] = 1
            } else {
                self.alarmStatus[raised_oid] = 0
            }
            self.updated = true
        }
    }
}

// AlarmTracker an aggregation plugin
type AlarmTracker struct {
    AlarmTag        string              `toml:"alarm_tag"`
	Identifiers     []string            `toml:"identifiers"`
    RaiseToClear    map[string]string   `toml:"alarms"`
    ClearToRaise    map[string]string
    ResetOnValues   []string            `toml:"reset_on_values"`

    // Database connection parameters
	URL             string              `toml:"url"`
    Database        string              `toml:"database"`
    Measurement     string              `toml:"measurement"`
	Username        string              `toml:"username"`
	Password        string              `toml:"password"`
	Timeout         internal.Duration   `toml:"timeout"`
	tls.ClientConfig

	client      *http.Client

	cache       TrackerCache

    Log         telegraf.Logger
}

// NewAlarmTracker create a new aggregation plugin which counts the occurrences
// of fields and emits the count.
func NewAlarmTracker() telegraf.Aggregator {
	tc := &AlarmTracker{
        AlarmTag:       "name",
        Identifiers:    []string{"host", "source"},
        ResetOnValues:  []string{"startupNotification"},
        URL:            "http://localhost:8086/query",
        Database:       "telegraf",
        Measurement:    "alarm"}
    tc.Reset()

	return tc
}

// SampleConfig generates a sample config for the AlarmTracker plugin
func (tc *AlarmTracker) SampleConfig() string {
	return sampleConfig
}

// Description returns the description of the AlarmTracker plugin
func (tc *AlarmTracker) Description() string {
	return "Count the occurrence of 'name' tag values, which are SNMP trap OIDs."
}

func (tc *AlarmTracker) TrackerID(tags map[string]string) uint64 {
    h := fnv.New64a()
    for _, key := range tc.Identifiers {
        h.Write([]byte(tags[key]))
        h.Write([]byte("\n"))
    }
    return h.Sum64()
}

func (self *AlarmTracker) GetTracker(tags map[string]string) *Tracker {
    var tracker *Tracker
    var ok bool

    // Calculate a tracked id from the metric's tags
    id := self.TrackerID(tags)

    // Check if the cache already has an entry for this metric.
    if tracker, ok = self.cache[id]; !ok {
        self.Log.Debugf("Creating new tracker for %s...", tags)
        // Not yet. Create trackers from existing database records.
        self.InitializeTrackers()
        // If still no aggregator, create one.
        if tracker, ok = self.cache[id]; !ok {
            tracker = self.CreateTracker(tags)
        }
    }

    return tracker
}

// Add is run on every metric which passes the plugin
func (self *AlarmTracker) Add(metric telegraf.Metric) {
    // Initialize ClearToRaise?
    if self.RaiseToClear != nil && self.ClearToRaise == nil {
        self.ClearToRaise = make(map[string]string)
        for k, v := range self.RaiseToClear {
            self.ClearToRaise[v] = k
        }
    }

    // Does this metric contain an alarm tag?
    if oid, ok := metric.GetTag(self.AlarmTag); ok {
        tracker := self.GetTracker(metric.Tags())

        // Did we get a notification that resets statuses?
        for _, reset_value := range self.ResetOnValues {
            if oid == reset_value {
                self.Log.Debugf("Received '%s'. Resetting.", oid)
                tracker.Reset()
                break
            }
        }

        tracker.SetAlarmStatus(oid)
	}
}

// Push emits the counters
func (self *AlarmTracker) Push(acc telegraf.Accumulator) {
	for _, tracker := range self.cache {
        if tracker.updated {
            fields := map[string]interface{}{}

            for alarm, status := range tracker.alarmStatus {
                fields[alarm] = status
            }

            acc.AddFields(self.Measurement, fields, tracker.tags)
        }
    }
}

// Reset the cache, executed after each push
func (self *AlarmTracker) Reset() {
    if self.cache == nil {
	    self.cache = make(TrackerCache)
    } else {
        for _, tracker := range self.cache {
            tracker.updated = false
        }
    }
}

func (self *AlarmTracker) CreateTracker(tags map[string]string) *Tracker {
    filtered_tags := make(map[string]string)
    for _, tag := range self.Identifiers {
        filtered_tags[tag] = tags[tag]
    }

    tracker := &Tracker{
        tags:           filtered_tags,
        alarmStatus:    make(map[string]int),
        plugin:         self,
        updated:        false,
    }
    self.cache[self.TrackerID(filtered_tags)] = tracker

    return tracker
}

// Initialize cache trapCount values from database
func (self *AlarmTracker) InitializeTrackers() {
    // Query database for initial counter values, which are the LAST() values in
    // the trap counting measurement

    // Create client
	if self.client == nil {
		tlsCfg, err := self.ClientConfig.TLSConfig()
		if err != nil {
			self.Log.Errorf("Failed to configure TLS - %s ", err)
            return
		}
		self.client = &http.Client{
			Transport: &http.Transport{
				ResponseHeaderTimeout: self.Timeout.Duration,
				TLSClientConfig:       tlsCfg,
			},
			Timeout: self.Timeout.Duration,
		}
	}

    // Create request
    v := url.Values{}
    v.Set("db", self.Database)
    v.Set("q",
        "SELECT LAST(*) FROM " + self.Measurement + " GROUP BY " +
        strings.Join(self.Identifiers, ", "))

    url := self.URL + "?" + v.Encode()

    self.Log.Debugf("Querying database: %s", url)
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        self.Log.Errorf("Failed to create HTTP request - %s", err)
        return
    }

    if self.Username != "" || self.Password != "" {
        req.SetBasicAuth(self.Username, self.Password)
    }

    req.Header.Set("User-Agent", "Telegraf/"+internal.Version())

    // Send request
    resp, err := self.client.Do(req);
    if err != nil {
        self.Log.Errorf("Failed to send requets - %s", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        var buf bytes.Buffer
        r := io.LimitReader(resp.Body, 1024)
        _, err := buf.ReadFrom(r)
        if err != nil {
            self.Log.Errorf("Failed to read error message - %s", err)
            return
        }

        type QueryError struct {
            Description string  `json:"error"`
        }
        var queryError QueryError

        err = json.Unmarshal(buf.Bytes(), queryError)
        if err != nil {
            self.Log.Errorf("Failed to parse error '%s' - %s",
                buf.String(), err)
            return
        }

        self.Log.Errorf("Request failed - %s:%s",
            resp.Status,
            queryError.Description)
        return
    }

    dec := json.NewDecoder(resp.Body)

    // Parse response object
    type Series struct {
        Name    string              `json:"name"`
        Tags    map[string]string   `json:"tags"`
        Columns []string            `json:"columns"`
        Values  [][]interface{}     `json:"values"`
    }

    type Result struct {
        Id      int                 `json:"statement_id"`
        Series  []Series            `json:"series"`
    }

    type Response struct {
        Results []Result            `json:"results"`
    }

    var response Response
    err = dec.Decode(&response);
    if err != nil {
        self.Log.Errorf("Failed to decode JSON - %s", err)
        return
    }

    // Response should have one Result containing many Series with one point
    // each
    self.Log.Debugf("%d series returned", len(response.Results[0].Series))

    for _, series := range response.Results[0].Series {
        log_entry := series.Name + ","
        for tag_key, tag_value := range series.Tags {
            log_entry += tag_key + "=" + tag_value + ";"
        }
        log_entry += " "

        // Create an aggregator with matching tags
        tracker := self.CreateTracker(series.Tags)
        // For all columns in the series whose name starts with "last_",
        // set oid to column name without the last_ prefix and
        // set agg.trapCount[oid] to the value at the same poisitions in
        // series.Values[0].
        for i, col := range series.Columns {
            if strings.HasPrefix(col, "last_") {
                alarm := strings.TrimPrefix(col, "last_")
                switch v := series.Values[0][i].(type) {
                    case float64:
                        tracker.alarmStatus[alarm] = int(v)
                        log_entry += alarm + "= " + string(int(v))
                    default:
                        tracker.alarmStatus[alarm] = 0
                        log_entry += alarm + "= 0"
                }
            }
        }
        self.Log.Debug(log_entry)
    }
}


func init() {
	aggregators.Add("alarmtracker", func() telegraf.Aggregator {
		return NewAlarmTracker()
	})
}

