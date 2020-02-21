package tagcounter

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

  ## Specific TagCounter Arguments:
  ## The tag keys whose values are counter
  count_tags = ["name"]

  ## The tags that supply the "GROUP BY" clause for initializing tag counts and
  ## are periodically output
  identifiers = ["host", "source"]

  ## Reset all counters if receive any of the tag values in the reset_on array
  reset_on_value = ["startupNotification"]
  ## Reset counters after every flush
  reset_on_flush = false
  ## Except for the counters listed in the dont_reset array
  dont_reset = ["startupNotification", "processExitedNotification", "missedHeartbeatNotification", "execvFailedNotification"]

  ## URL from which to read InfluxDB-formatted JSON
  ## Default is "http://localhost:8086/query".
  url = "http://localhost:8086/query"
  ## Database and measurement values used to build the LAST() query. The
  ## following values, in combination with the url and identifiers parameters above
  ## would build a final url: 
  ## http://localhost:8086/query?db=telegraf&q=SELECT LAST(*) FROM tag_count GROUP BY host, source
  database = "telegraf"
  measurement = "tag_count"

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

type aggregate struct {
	tags        map[string]string
	tagCount    map[string]int
    updated     bool
    plugin      *TagCounter
}

type AggregateCache map[uint64]*aggregate

func (self *aggregate) UpdateCounts(values []string) {
    for _, value := range values {
        self.tagCount[value]++
        self.plugin.Log.Debugf("'%s': %d -> %d",
            value, self.tagCount[value] - 1, self.tagCount[value])
	}
    self.updated = true
}

func (self *aggregate) Reset() {
    for key, _ := range self.tagCount {
        for _, dont_reset := range self.plugin.DontReset {
            if key != dont_reset {
                self.tagCount[key] = 0
            }
        }
    }
}

// TagCounter an aggregation plugin
type TagCounter struct {
    CountTags       []string    `toml:"count_tags"`
	Identifiers     []string    `toml:"identifiers"`
    ResetOnFlush    bool        `toml:"reset_on_flush"`
    ResetOnValues   []string    `toml:"reset_on_values"`
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

// NewTagCounter create a new aggregation plugin which counts the occurrences
// of fields and emits the count.
func NewTagCounter() telegraf.Aggregator {
	tc := &TagCounter{
        CountTags:      []string{"name"},
        Identifiers:    []string{"host", "source"},
        ResetOnValues:  []string{"startupNotification"},
        DontReset:      []string{"startupNotification",
                                 "processExitedNotification",
                                 "missedHeartbeatNotification",
                                 "execvFailedNotification"},
        URL:            "http://localhost:8086/query",
        Database:       "telegraf",
        Measurement:    "tag_count"}
    tc.Reset()

	return tc
}

// SampleConfig generates a sample config for the TagCounter plugin
func (tc *TagCounter) SampleConfig() string {
	return sampleConfig
}

// Description returns the description of the TagCounter plugin
func (tc *TagCounter) Description() string {
	return "Count the occurrence of tag values."
}

func (tc *TagCounter) AggregateID(tags map[string]string) uint64 {
    h := fnv.New64a()
    for _, key := range tc.Identifiers {
        h.Write([]byte(tags[key]))
        h.Write([]byte("\n"))
    }
    return h.Sum64()
}

func (self *TagCounter) GetAggregate(tags map[string]string) *aggregate {
    var a *aggregate
    var ok bool

    id := self.AggregateID(tags)

	// Check if the cache already has an entry for this metric, if not create it
	if a, ok = self.cache[id]; !ok {
        self.Log.Debugf("Creating new aggregate for %s...", tags)
        self.InitializeAggregates()
        // If still no aggregator, create one
        if a, ok = self.cache[id]; !ok {
            a = self.CreateAggregate(tags)
        }
	}

    return a
}

func (self *TagCounter) Add(metric telegraf.Metric) {
    // Collect the values for tags this aggregator is interested in
    values := []string{}
    for _, key := range self.CountTags {
        if value, ok := metric.GetTag(key); ok {
            values = append(values, value)
        }
    }

    // If there are values to count...
    if len(values) > 0 {
        a := self.GetAggregate(metric.Tags())

        // Did we get a notification that resets counts?
        for _, tag := range values {
            for _, reset_value := range self.ResetOnValues {
                if tag == reset_value {
                    self.Log.Debugf("Received '%s'. Resetting.", tag)
                    a.Reset()
                    break
                }
            }
        }

        a.UpdateCounts(values)
    }
}

// Push emits the counters
func (self *TagCounter) Push(acc telegraf.Accumulator) {
	for _, agg := range self.cache {
        if agg.updated {
            fields := map[string]interface{}{}
            for key, value := range agg.tagCount {
                fields[key] = value
            }

            acc.AddFields(self.Measurement, fields, agg.tags)
        }
    }
}

// Reset the cache, executed after each push
func (self *TagCounter) Reset() {
    if self.cache == nil {
	    self.cache = make(AggregateCache)
    } else {
        for _, a := range self.cache {
            if self.ResetOnFlush {
                a.Reset()
            }
            a.updated = false
        }
    }
}

func (self *TagCounter) CreateAggregate(tags map[string]string) *aggregate {
    filtered_tags := make(map[string]string)
    for _, tag := range self.Identifiers {
        filtered_tags[tag] = tags[tag]
    }

    a := &aggregate{
        tags:       filtered_tags,
        tagCount:   make(map[string]int),
        plugin:     self}
    self.cache[self.AggregateID(filtered_tags)] = a

    return a
}

// Initialize cache tagCount values from database
func (tc *TagCounter) InitializeAggregates() {
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
        agg := tc.CreateAggregate(series.Tags)
        // For all columns in the series whose name starts with "last_",
        // set key to column name without the last_ prefix and
        // set agg.tagCount[key] to the value at the same poisitions in
        // series.Values[0].
        for i, col := range series.Columns {
            if strings.HasPrefix(col, "last_") {
                key := strings.TrimPrefix(col, "last_")
                switch v := series.Values[0][i].(type) {
                    case float64:
                        agg.tagCount[key] = int(v)
                        log_entry += key + "=" + string(int(v))
                    default:
                        agg.tagCount[key] = 0
                        log_entry += key + "=0"
                }
            }
        }
        tc.Log.Debug(log_entry)
    }
}


func init() {
	aggregators.Add("tagcounter", func() telegraf.Aggregator {
		return NewTagCounter()
	})
}

