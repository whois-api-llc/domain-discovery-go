package domaindiscovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

const (
	pathDomainDiscoveryResponseOK         = "/DomainDiscovery/ok"
	pathDomainDiscoveryResponseError      = "/DomainDiscovery/error"
	pathDomainDiscoveryResponse500        = "/DomainDiscovery/500"
	pathDomainDiscoveryResponsePartial1   = "/DomainDiscovery/partial"
	pathDomainDiscoveryResponsePartial2   = "/DomainDiscovery/partial2"
	pathDomainDiscoveryResponseUnparsable = "/DomainDiscovery/unparsable"
)

const apiKey = "at_LoremIpsumDolorSitAmetConsect"

// dummyServer is the sample of the Domains & Subdomains Discovery API server for testing.
func dummyServer(resp, respUnparsable string, respErr string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var response string

		response = resp

		switch req.URL.Path {
		case pathDomainDiscoveryResponseOK:
		case pathDomainDiscoveryResponseError:
			w.WriteHeader(499)
			response = respErr
		case pathDomainDiscoveryResponse500:
			w.WriteHeader(500)
			response = respUnparsable
		case pathDomainDiscoveryResponsePartial1:
			response = response[:len(response)-10]
		case pathDomainDiscoveryResponsePartial2:
			w.Header().Set("Content-Length", strconv.Itoa(len(response)))
			response = response[:len(response)-10]
		case pathDomainDiscoveryResponseUnparsable:
			response = respUnparsable
		default:
			panic(req.URL.Path)
		}
		_, err := w.Write([]byte(response))
		if err != nil {
			panic(err)
		}
	}))

	return server
}

// newAPI returns new Domains & Subdomains Discovery API client for testing.
func newAPI(apiServer *httptest.Server, link string) *Client {
	apiURL, err := url.Parse(apiServer.URL)
	if err != nil {
		panic(err)
	}

	apiURL.Path = link

	params := ClientParams{
		HTTPClient:             apiServer.Client(),
		DomainDiscoveryBaseURL: apiURL,
	}

	return NewClient(apiKey, params)
}

// TestDomainDiscoveryGet tests the Get function.
func TestDomainDiscoveryGet(t *testing.T) {
	checkResultRec := func(res *DomainDiscoveryResponse) bool {
		return res != nil
	}

	ctx := context.Background()

	const resp = `{"domainsCount":5,"domainsList":["internet-retailers.whoisxmlapi.com",
"threat-intelligence.whoisxmlapi.com","domain-reputation.whoisxmlapi.com","newly-created-websites.whoisxmlapi.com",
"registrant-alert-api.whoisxmlapi.com"]}`

	const respUnparsable = `<?xml version="1.0" encoding="utf-8"?><>`

	const errResp = `{"code":499,"messages":"Test error message."}`

	server := dummyServer(resp, respUnparsable, errResp)
	defer server.Close()

	type options struct {
		mandatory *SearchTerms
		option    Option
	}

	type args struct {
		ctx     context.Context
		options options
	}

	tests := []struct {
		name    string
		path    string
		args    args
		want    bool
		wantErr string
	}{
		{
			name: "successful request",
			path: pathDomainDiscoveryResponseOK,
			args: args{
				ctx: ctx,
				options: options{
					&SearchTerms{[]string{"whoisxmlapi*"}, nil},
					OptionOutputFormat("JSON"),
				},
			},
			want:    true,
			wantErr: "",
		},
		{
			name: "non 200 status code",
			path: pathDomainDiscoveryResponse500,
			args: args{
				ctx: ctx,
				options: options{
					&SearchTerms{[]string{"whoisxmlapi*"}, nil},
					OptionOutputFormat("JSON"),
				},
			},
			want:    false,
			wantErr: "cannot parse response: invalid character '<' looking for beginning of value",
		},
		{
			name: "partial response 1",
			path: pathDomainDiscoveryResponsePartial1,
			args: args{
				ctx: ctx,
				options: options{
					&SearchTerms{[]string{"whoisxmlapi*"}, nil},
					OptionOutputFormat("JSON"),
				},
			},
			want:    false,
			wantErr: "cannot parse response: unexpected EOF",
		},
		{
			name: "partial response 2",
			path: pathDomainDiscoveryResponsePartial2,
			args: args{
				ctx: ctx,
				options: options{
					&SearchTerms{[]string{"whoisxmlapi*"}, nil},
					OptionOutputFormat("JSON"),
				},
			},
			want:    false,
			wantErr: "cannot read response: unexpected EOF",
		},
		{
			name: "could not process request",
			path: pathDomainDiscoveryResponseError,
			args: args{
				ctx: ctx,
				options: options{
					&SearchTerms{[]string{"whoisxmlapi*"}, nil},
					OptionOutputFormat("JSON"),
				},
			},
			want:    false,
			wantErr: "API error: [499] Test error message.",
		},
		{
			name: "unparsable response",
			path: pathDomainDiscoveryResponseUnparsable,
			args: args{
				ctx: ctx,
				options: options{
					&SearchTerms{[]string{"whoisxmlapi*"}, nil},
					OptionOutputFormat("XML"),
				},
			},
			want:    false,
			wantErr: "cannot parse response: invalid character '<' looking for beginning of value",
		},
		{
			name: "invalid argument1",
			path: pathDomainDiscoveryResponseError,
			args: args{
				ctx: ctx,
				options: options{
					&SearchTerms{nil, []string{"whoisxmlapi.com"}},
					OptionOutputFormat("JSON"),
				},
			},
			want:    false,
			wantErr: `invalid argument: "domainTerms/subdomainTerms" must contain at least one Include term`,
		},
		{
			name: "invalid argument2",
			path: pathDomainDiscoveryResponseError,
			args: args{
				ctx: ctx,
				options: options{
					nil,
					OptionOutputFormat("JSON"),
				},
			},
			want:    false,
			wantErr: `invalid argument: "domainTerms/subdomainTerms" must contain at least one Include term`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := newAPI(server, tt.path)

			gotRec, _, err := api.Get(tt.args.ctx, tt.args.options.mandatory, nil, tt.args.options.option)
			if (err != nil || tt.wantErr != "") && (err == nil || err.Error() != tt.wantErr) {
				t.Errorf("DomainDiscovery.Get() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if tt.want {
				if !checkResultRec(gotRec) {
					t.Errorf("DomainDiscovery.Get() got = %v, expected something else", gotRec)
				}
			} else {
				if gotRec != nil {
					t.Errorf("DomainDiscovery.Get() got = %v, expected nil", gotRec)
				}
			}
		})
	}
}

// TestDomainDiscoveryGetRaw tests the GetRaw function.
func TestDomainDiscoveryGetRaw(t *testing.T) {
	checkResultRaw := func(res []byte) bool {
		return len(res) != 0
	}

	ctx := context.Background()

	const resp = `{"domainsCount":5,"domainsList":["internet-retailers.whoisxmlapi.com",
"threat-intelligence.whoisxmlapi.com","domain-reputation.whoisxmlapi.com","newly-created-websites.whoisxmlapi.com",
"registrant-alert-api.whoisxmlapi.com"]}`

	const respUnparsable = `<?xml version="1.0" encoding="utf-8"?><>`

	const errResp = `{"code":499,"messages":"Test error message."}`

	server := dummyServer(resp, respUnparsable, errResp)
	defer server.Close()

	type options struct {
		mandatory *SearchTerms
		option    Option
	}

	type args struct {
		ctx     context.Context
		options options
	}

	tests := []struct {
		name    string
		path    string
		args    args
		wantErr string
	}{
		{
			name: "successful request",
			path: pathDomainDiscoveryResponseOK,
			args: args{
				ctx: ctx,
				options: options{
					&SearchTerms{[]string{"whoisxmlapi*"}, nil},
					OptionOutputFormat("JSON"),
				},
			},
			wantErr: "",
		},
		{
			name: "non 200 status code",
			path: pathDomainDiscoveryResponse500,
			args: args{
				ctx: ctx,
				options: options{
					&SearchTerms{[]string{"whoisxmlapi*"}, nil},
					OptionOutputFormat("JSON"),
				},
			},
			wantErr: "API failed with status code: 500",
		},
		{
			name: "partial response 1",
			path: pathDomainDiscoveryResponsePartial1,
			args: args{
				ctx: ctx,
				options: options{
					&SearchTerms{[]string{"whoisxmlapi*"}, nil},
					OptionOutputFormat("JSON"),
				},
			},
			wantErr: "",
		},
		{
			name: "partial response 2",
			path: pathDomainDiscoveryResponsePartial2,
			args: args{
				ctx: ctx,
				options: options{
					&SearchTerms{[]string{"whoisxmlapi*"}, nil},
					OptionOutputFormat("JSON"),
				},
			},
			wantErr: "cannot read response: unexpected EOF",
		},
		{
			name: "unparsable response",
			path: pathDomainDiscoveryResponseUnparsable,
			args: args{
				ctx: ctx,
				options: options{
					&SearchTerms{[]string{"whoisxmlapi*"}, nil},
					OptionOutputFormat("XML"),
				},
			},
			wantErr: "",
		},
		{
			name: "could not process request",
			path: pathDomainDiscoveryResponseError,
			args: args{
				ctx: ctx,
				options: options{
					&SearchTerms{[]string{"whoisxmlapi*"}, nil},
					OptionOutputFormat("JSON"),
				},
			},
			wantErr: "API failed with status code: 499",
		},
		{
			name: "invalid argument1",
			path: pathDomainDiscoveryResponseError,
			args: args{
				ctx: ctx,
				options: options{
					&SearchTerms{nil, nil},
					OptionOutputFormat("JSON"),
				},
			},
			wantErr: `invalid argument: "domainTerms/subdomainTerms" must contain at least one Include term`,
		},
		{
			name: "invalid argument2",
			path: pathDomainDiscoveryResponseError,
			args: args{
				ctx: ctx,
				options: options{
					&SearchTerms{nil, []string{"whoisxmlapi.com"}},
					OptionOutputFormat("JSON"),
				},
			},
			wantErr: `invalid argument: "domainTerms/subdomainTerms" must contain at least one Include term`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := newAPI(server, tt.path)

			resp, err := api.GetRaw(tt.args.ctx, tt.args.options.mandatory, nil)
			if (err != nil || tt.wantErr != "") && (err == nil || err.Error() != tt.wantErr) {
				t.Errorf("DomainDiscovery.GetRaw() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if resp != nil && !checkResultRaw(resp.Body) {
				t.Errorf("DomainDiscovery.GetRaw() got = %v, expected something else", string(resp.Body))
			}
		})
	}
}
