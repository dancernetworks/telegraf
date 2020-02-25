package parsers

import (
	"fmt"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/parsers/grok"
)

// Creator is the function to create a new parser
type Creator func(defaultMetricName string) telegraf.Parser

// Parsers contains the registry of all known parsers (following the new style)
var Parsers = map[string]Creator{}

// Add adds a parser to the registry. Usually this function is called in the plugin's init function
func Add(name string, creator Creator) {
	Parsers[name] = creator
}

type ParserFunc func() (Parser, error)

// ParserInput is an interface for input plugins that are able to parse
// arbitrary data formats.
type ParserInput interface {
	// SetParser sets the parser function for the interface
	SetParser(parser Parser)
}

// ParserFuncInput is an interface for input plugins that are able to parse
// arbitrary data formats.
type ParserFuncInput interface {
	// GetParser returns a new parser.
	SetParserFunc(fn ParserFunc)
}

// Parser is an interface defining functions that a parser plugin must satisfy.
type Parser interface {
	// Parse takes a byte buffer separated by newlines
	// ie, `cpu.usage.idle 90\ncpu.usage.busy 10`
	// and parses it into telegraf metrics
	//
	// Must be thread-safe.
	Parse(buf []byte) ([]telegraf.Metric, error)

	// ParseLine takes a single string metric
	// ie, "cpu.usage.idle 90"
	// and parses it into a telegraf metric.
	//
	// Must be thread-safe.
	// This function is only called by plugins that expect line based protocols
	// Doesn't need to be implemented by non-linebased parsers (e.g. json, xml)
	ParseLine(line string) (telegraf.Metric, error)

	IsMultiline() bool

	IsNewLogLine(line string) (bool, error)

	// SetDefaultTags tells the parser to add all of the given tags
	// to each parsed metric.
	// NOTE: do _not_ modify the map after you've passed it here!!
	SetDefaultTags(tags map[string]string)
}

// Config is a struct that covers the data types needed for all parser types,
// and can be used to instantiate _any_ of the parsers.
type Config struct {
	// Dataformat can be one of: json, influx, graphite, value, nagios
	DataFormat string `toml:"data_format"`

	// Separator only applied to Graphite data.
	Separator string `toml:"separator"`
	// Templates only apply to Graphite data.
	Templates []string `toml:"templates"`

	// TagKeys only apply to JSON data
	TagKeys []string `toml:"tag_keys"`
	// Array of glob pattern strings keys that should be added as string fields.
	JSONStringFields []string `toml:"json_string_fields"`

	JSONNameKey string `toml:"json_name_key"`
	// MetricName applies to JSON & value. This will be the name of the measurement.
	MetricName string `toml:"metric_name"`

	// holds a gjson path for json parser
	JSONQuery string `toml:"json_query"`

	// key of time
	JSONTimeKey string `toml:"json_time_key"`

	// time format
	JSONTimeFormat string `toml:"json_time_format"`

	// default timezone
	JSONTimezone string `toml:"json_timezone"`

	// Whether to continue if a JSON object can't be coerced
	JSONStrict bool `toml:"json_strict"`

	// Authentication file for collectd
	CollectdAuthFile string `toml:"collectd_auth_file"`
	// One of none (default), sign, or encrypt
	CollectdSecurityLevel string `toml:"collectd_security_level"`
	// Dataset specification for collectd
	CollectdTypesDB []string `toml:"collectd_types_db"`

	// whether to split or join multivalue metrics
	CollectdSplit string `toml:"collectd_split"`

	// DataType only applies to value, this will be the type to parse value to
	DataType string `toml:"data_type"`

	// DefaultTags are the default tags that will be added to all parsed metrics.
	DefaultTags map[string]string `toml:"default_tags"`

	//grok patterns
	GrokPatterns           []string `toml:"grok_patterns"`
	GrokNamedPatterns      []string `toml:"grok_named_patterns"`
	GrokCustomPatterns     string   `toml:"grok_custom_patterns"`
	GrokCustomPatternFiles []string `toml:"grok_custom_pattern_files"`
	GrokTimezone           string   `toml:"grok_timezone"`
	GrokUniqueTimestamp    string   `toml:"grok_unique_timestamp"`
}

// NewParser returns a Parser interface based on the given config.
func NewParser(config *Config) (Parser, error) {
	var err error
	var parser Parser
	switch config.DataFormat {
	case "grok":
		parser, err = newGrokParser(
			config.MetricName,
			config.GrokPatterns,
			config.GrokNamedPatterns,
			config.GrokCustomPatterns,
			config.GrokCustomPatternFiles,
			config.GrokTimezone,
			config.GrokUniqueTimestamp)
	default:
		err = fmt.Errorf("Invalid data format: %s", config.DataFormat)
	}
	return parser, err
}

func newGrokParser(metricName string,
	patterns []string, nPatterns []string,
	cPatterns string, cPatternFiles []string,
	tZone string, uniqueTimestamp string) (Parser, error) {
	parser := grok.Parser{
		Measurement:        metricName,
		Patterns:           patterns,
		NamedPatterns:      nPatterns,
		CustomPatterns:     cPatterns,
		CustomPatternFiles: cPatternFiles,
		Timezone:           tZone,
		UniqueTimestamp:    uniqueTimestamp,
	}

	err := parser.Compile()
	return &parser, err
}
