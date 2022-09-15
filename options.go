package domaindiscovery

import (
	"strings"
	"time"
)

// Option adds parameters to the query.
type Option func(v *domainDiscoveryRequest)

var _ = []Option{
	OptionOutputFormat("JSON"),
	OptionSinceDate(time.Time{}),
}

const dateFormat = "2006-01-02"

// OptionOutputFormat sets Response output format JSON | XML. Default: JSON.
func OptionOutputFormat(outputFormat string) Option {
	return func(v *domainDiscoveryRequest) {
		v.OutputFormat = strings.ToUpper(outputFormat)
	}
}

// OptionSinceDate results search through domains/subdomains discovered since the given date.
func OptionSinceDate(date time.Time) Option {
	return func(v *domainDiscoveryRequest) {
		v.SinceDate = date.Format(dateFormat)
	}
}
