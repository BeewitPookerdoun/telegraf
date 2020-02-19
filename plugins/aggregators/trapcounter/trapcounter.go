package trapcounter

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

type aggregate struct {
	name        string
	tags        map[string]string
	trapCount   map[string]int
    added       bool
}

// TrapCounter an aggregation plugin
type AggregateCache map[uint64]*aggregate
type TrapCounter struct {
	Identifiers []string    `toml:"identifiers"`
    ResetCounts bool        `toml:"reset"`

    ResetOn         []string    `toml:"reset_on"`
    DontReset       []string    `toml:"dont_reset"`

    // Database connection parameters
	URL         string            `toml:"url"`
    Database    string            `toml:"database"`
    Measurement string            `toml:"measurement"`
	Username    string            `toml:"username"`
	Password    string            `toml:"password"`
	Timeout     internal.Duration `toml:"timeout"`
	tls.ClientConfig

	client      *http.Client

	cache       AggregateCache

    Log         telegraf.Logger

    init        bool
}

// NewTrapCounter create a new aggregation plugin which counts the occurrences
// of fields and emits the count.
func NewTrapCounter() telegraf.Aggregator {
	tc := &TrapCounter{}
    tc.Reset()

	return tc
}

var sampleConfig = `
  ## General Aggregator Arguments:
  ## The period on which to flush & clear the aggregator.
  period = "30s"
  ## If true, the original metric will be dropped by the
  ## aggregator and will not get sent to the output plugins.
  drop_original = false

  ## Specific TrapCounter Arguments:
  ## The tags that supply the "GROUP BY" clause for initializing trap counts and
  ## are periodically output
  identifiers = ["host", "source"]

  ## The trapcounter plugin decrements counts (down to 0) when it receives a
  ## "clear" notification.
  ## Unless the notification OID is found in the "alarm_pairs" table, its
  ## opposite ("raised" vs. "cleared") is determined by the presence/absence of
  ## the suffix "Clear". For OIDs that don't follow this convention, add an
  ## entry in the "alarm_pairs" table where the key is the "cleared" OID and
  ## the value is the "raised" one. For example,
  ##
  ## [aggregators.trapcounter.alarm_pairs]
  ##   theAlarmIsNowInactive = anAlarmWasRaised
  ##
  ## The plugin resets all other counters to 0 if it receives any of the OIDs in
  ## the reset_on array
  reset_on = ["startupNotification"]
  ## Except for the OIDs listed in the dont_reset array
  dont_reset = ["processExitedNotification", "missedHeartbeatNotification", "execvFailedNotification"]

  ## Reset counters after every flush
  reset = false

  ## URL from which to read InfluxDB-formatted JSON
  ## Default is "http://localhost:8086/query".
  url = "http://localhost:8086/query"
  ## Database and measurement values used to build the LAST() query. The
  ## following values, in combination with the url and identifiers parameters above
  ## would build a final url: 
  ## http://localhost:8086/query?db=telegraf&q=SELECT LAST(*) FROM snmp_trap GROUP BY host, source
  database = "telegraf"
  measurement = "snmp_trap"

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

// SampleConfig generates a sample config for the TrapCounter plugin
func (tc *TrapCounter) SampleConfig() string {
	return sampleConfig
}

// Description returns the description of the TrapCounter plugin
func (tc *TrapCounter) Description() string {
	return "Count the occurrence of 'name' tag values, which are SNMP trap OIDs."
}

func (tc *TrapCounter) AggregateID(tags map[string]string) uint64 {
    h := fnv.New64a()
    for _, key := range tc.Identifiers {
        h.Write([]byte(tags[key]))
        h.Write([]byte("\n"))
    }
    return h.Sum64()
}

func (tc *TrapCounter) GetRaisedOID(oid string) (string, bool) {
    // Is oid in ClearedToRaised?
    if raised_oid, ok := tc.ClearedToRaised[oid]; ok {
        tc.Log.Debugf("OID '%s' found in ClearedToRaised", oid)
        return raised_oid, true
    // or does it have the suffix "Clear"?
    } else if strings.HasSuffix(oid, "Clear") {
        tc.Log.Debugf("OID '%s' has 'Clear' suffix", oid)
        return strings.TrimSuffix(oid, "Clear"), true
    // No? Then it's a notification that an alarm has been raised.
    } else {
        return oid, false
    }
}

// Add is run on every metric which passes the plugin
func (tc *TrapCounter) Add(in telegraf.Metric) {
    // Use metric's source address as cache key
	id := tc.AggregateID(in.Tags())

	// Check if the cache already has an entry for this metric, if not create it
	if _, ok := tc.cache[id]; !ok {
        tc.Log.Debugf("Creating new aggregate for %s...", in.Tags())
        tc.InitializeAggregators()
        // If still no aggregator, create one
        if _, ok := tc.cache[id]; !ok {
            tc.CreateAggregator(in.Name(), in.Tags())
        }
	}

    // TODO: Parameterize "name"?
	// Check if this metric has a "name" tag. If so, increment its value's hit
    // count.
    if oid, ok := in.GetTag("name"); ok {
        agg := tc.cache[id]

        // Decrement trap count on clear (down to 0), increment on raise
        raised_oid, is_clear := tc.GetRaisedOID(oid)
        if is_clear {
            if agg.trapCount[raised_oid] > 0 {
                agg.trapCount[raised_oid]--
            }
        } else {
            agg.trapCount[raised_oid]++
        }

        agg.added = true
	}
}

// Push emits the counters
func (tc *TrapCounter) Push(acc telegraf.Accumulator) {
	for _, agg := range tc.cache {
        if agg.added {
            oids := map[string]interface{}{}

            for oid, count := range agg.trapCount {
                oids[oid] = count
            }

            acc.AddFields(agg.name, oids, agg.tags)
        }
    }
}

// Reset the cache, executed after each push
func (tc *TrapCounter) Reset() {
    if tc.cache == nil {
	    tc.cache = make(AggregateCache)
    } else {
        for _, agg := range tc.cache {
            for oid, _ := range agg.trapCount {
                if tc.ResetCounts {
                    agg.trapCount[oid] = 0
                }
                agg.added = false
            }
        }
    }
}

func (tc *TrapCounter) CreateAggregator(name string, tags map[string]string) *aggregate {
    filtered_tags := make(map[string]string)
    for _, tag := range tc.Identifiers {
        filtered_tags[tag] = tags[tag]
    }

    a := &aggregate{
        name:       name,
        tags:       filtered_tags,
        trapCount:  make(map[string]int),
    }
    tc.cache[tc.AggregateID(filtered_tags)] = a

    return a
}

// Initialize cache trapCount values from database
func (tc *TrapCounter) InitializeAggregators() {
    // Query database for initial counter values, which are the LAST() values in
    // the trap counting measurement

    // Create client
	if tc.client == nil {
		tlsCfg, err := tc.ClientConfig.TLSConfig()
		if err != nil {
			tc.Log.Errorf("Failed to configure TLS - %s ", err)
            return
		}
		tc.client = &http.Client{
			Transport: &http.Transport{
				ResponseHeaderTimeout: tc.Timeout.Duration,
				TLSClientConfig:       tlsCfg,
			},
			Timeout: tc.Timeout.Duration,
		}
	}

    // Create request
    query := "SELECT LAST(*) FROM " +
        tc.Measurement +
        " GROUP BY " +
        strings.Join(tc.Identifiers, ", ")

    v := url.Values{}
    v.Set("db", tc.Database)
    v.Set("q", query)

    url := tc.URL + "?" + v.Encode()

    tc.Log.Debugf("Querying database: %s", url)
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        tc.Log.Errorf("Failed to create HTTP request - %s", err)
        return
    }

    if tc.Username != "" || tc.Password != "" {
        req.SetBasicAuth(tc.Username, tc.Password)
    }

    req.Header.Set("User-Agent", "Telegraf/"+internal.Version())

    // Send request
    resp, err := tc.client.Do(req);
    if err != nil {
        tc.Log.Errorf("Failed to send requets - %s", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        var buf bytes.Buffer
        r := io.LimitReader(resp.Body, 1024)
        _, err := buf.ReadFrom(r)
        if err != nil {
            tc.Log.Errorf("Failed to read error message - %s", err)
            return
        }

        type QueryError struct {
            Description string  `json:"error"`
        }
        var queryError QueryError

        err = json.Unmarshal(buf.Bytes(), queryError)
        if err != nil {
            tc.Log.Errorf("Failed to parse error '%s' - %s",
                buf.String(), err)
            return
        }

        tc.Log.Errorf("Request failed - %s:%s",
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
        tc.Log.Errorf("Failed to decode JSON - %s", err)
        return
    }

    // Response should have one Result containing many Series with one point
    // each
    tc.Log.Debugf("%d series returned", len(response.Results[0].Series))

    for _, series := range response.Results[0].Series {
        log_entry := series.Name + ","
        for tag_key, tag_value := range series.Tags {
            log_entry += tag_key + "=" + tag_value + ";"
        }
        log_entry += " "

        // Create an aggregator with matching tags
        agg := tc.CreateAggregator(series.Name, series.Tags)
        // For all columns in the series whose name starts with "last_",
        // set oid to column name without the last_ prefix and
        // set agg.trapCount[oid] to the value at the same poisitions in
        // series.Values[0].
        for i, col := range series.Columns {
            if strings.HasPrefix(col, "last_") {
                oid := strings.TrimPrefix(col, "last_")
                switch v := series.Values[0][i].(type) {
                    case float64:
                        agg.trapCount[oid] = int(v)
                        log_entry += oid + "=" + string(int(v))
                    default:
                        agg.trapCount[oid] = 0
                        log_entry += oid + "=0"
                }
            }
        }
        tc.Log.Debug(log_entry)
    }
}


func init() {
	aggregators.Add("trapcounter", func() telegraf.Aggregator {
		return NewTrapCounter(
            ResetOn: ["startupNotification"]
            DontReset: ["processExitedNotification",
                "missedHeartbeatNotification", "execvFailedNotification"]
            URL: "http://localhost:8086/query"
            Identifiers: ["host", "source"]
            Measurement: "snmp_trap"
            Database: "telegraf"
        )
	})
}

