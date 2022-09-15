package domaindiscovery

import (
	"reflect"
	"testing"
	"time"
)

// TestOptions tests the Options functions.
func TestOptions(t *testing.T) {
	tests := []struct {
		name   string
		values *domainDiscoveryRequest
		option Option
		want   string
	}{
		{
			name:   "outputFormat",
			values: &domainDiscoveryRequest{},
			option: OptionOutputFormat("JSON"),
			want:   "JSON",
		},
		{
			name:   "sinceDate",
			values: &domainDiscoveryRequest{},
			option: OptionSinceDate(time.Date(2021, 01, 01, 0, 0, 0, 0, time.UTC)),
			want:   "2021-01-01",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			tt.option(tt.values)

			switch tt.name {
			case "outputFormat":
				got = tt.values.OutputFormat
			case "sinceDate":
				got = tt.values.SinceDate
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Option() = %v, want %v", got, tt.want)
			}
		})
	}
}
