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

  ## Also initialize the "opposite" clear/raise value when receiving a
  ## notification for the first time.
  ## The regular expression to compare to an existing notification OID for
  ## for formatting its opposite notification
  clear_regexp = "^(.*)Clear$"

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

// Add is run on every metric which passes the plugin
func (tc *TrapCounter) Add(in telegraf.Metric) {
    // Use metric's source address as cache key
	id := tc.AggregateID(in.Tags())

	// Check if the cache already has an entry for this metric, if not create it
	if _, ok := tc.cache[id]; !ok {
        tc.Log.Debugf("Failed to find an aggregate for %s. Creating one...", in.Tags())
        tc.InitializeAggregators()
        // If still no aggregator, create one
        if _, ok := tc.cache[id]; !ok {
            tc.CreateAggregator(in.Name(), in.Tags())
        }
	}

    // TODO: Parameterize "name"
	// Check if this metric has a "name" tag. If so, increment its value's hit
    // count.
    if oid, ok := in.GetTag("name"); ok {
        agg = tc.cache[id]
        if _, ok = agg.trapCount[oid]; !ok {
            // Initialize the notification OID's counter to 1
            agg.trapCount[oid] = 1

            // Initialize the OID's "opposite" to 0
            if tc.ClearExpr == "" {
                tc.ClearExpr = "^(.*)Clear$"
            }
            if tc.ClearRegexp == nil {
                tc.ClearRegexp = regexp.MustCompile(tc.ClearExpr)
            }
            matches := tc.ClearRegexp.FindStringSubmatch(oid)
            if matches == nil {
                // Is a "raise", initialize "clear"
            } else {
                // Is a "clear", initialize "raise"
                agg.trapCount[matches[1]] = 0
            }
        } else {
            tc.cache[id].trapCount[oid]++
        }
        tc.cache[id].added = true
	}
}

// Push emits the counters
func (tc *TrapCounter) Push(acc telegraf.Accumulator) {
	for _, agg := range tc.cache {
        if agg.added {
            tc.Log.Debugf("*PUSH* Sending aggregate %s to accumulator.", agg.tags)
            oids := map[string]interface{}{}

            for oid, count := range agg.trapCount {
                oids[oid] = count
            }

            acc.AddFields(agg.name, oids, agg.tags)
        } else {
            tc.Log.Debugf("*PUSH* No new metrics for aggregate %s.", agg.tags)
        }
	}
}

// Reset the cache, executed after each push
func (tc *TrapCounter) Reset() {
    if tc.Log != nil {
        tc.Log.Debugf("*RESET*")
    }
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

    // Set default url
	if tc.URL == "" {
		tc.URL = "http://localhost:8086/query"
	}

    if len(tc.Identifiers) == 0 {
        tc.Identifiers[0] = "host"
        tc.Identifiers[1] = "source"
    }

    if tc.Measurement == "" {
        tc.Measurement = "snmp_trap"
    }

    if tc.Database == "" {
        tc.Database = "telegraf"
    }

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
		return NewTrapCounter()
	})
}

