package domaindiscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// DomainDiscovery is an interface for Domains & Subdomains Discovery API.
type DomainDiscovery interface {
	// Get returns parsed Domains & Subdomains Discovery API response.
	Get(ctx context.Context, domainTerms *SearchTerms, subdomainTerms *SearchTerms, option ...Option) (*DomainDiscoveryResponse, *Response, error)

	// GetRaw returns raw Domains & Subdomains Discovery API response as the Response struct with Body saved as a byte slice.
	GetRaw(ctx context.Context, domainTerms *SearchTerms, subdomainTerms *SearchTerms, option ...Option) (*Response, error)
}

// Response is the http.Response wrapper with Body saved as a byte slice.
type Response struct {
	*http.Response

	// Body is the byte slice representation of http.Response Body
	Body []byte
}

// domainDiscoveryServiceOp is the type implementing the DomainDiscovery interface.
type domainDiscoveryServiceOp struct {
	client  *Client
	baseURL *url.URL
}

var _ DomainDiscovery = &domainDiscoveryServiceOp{}

// newRequest creates the API request with default parameters and specified body.
func (service domainDiscoveryServiceOp) newRequest(body []byte) (*http.Request, error) {
	req, err := service.client.NewRequest(http.MethodPost, service.baseURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	return req, nil
}

// apiResponse is used for parsing Domains & Subdomains Discovery API response as a model instance.
type apiResponse struct {
	DomainDiscoveryResponse
	ErrorMessage
}

// request returns intermediate API response for further actions.
func (service domainDiscoveryServiceOp) request(
	ctx context.Context,
	domainTerms *SearchTerms, subdomainTerms *SearchTerms,
	opts ...Option) (*Response, error) {
	if domainTerms == nil && subdomainTerms == nil ||
		(domainTerms == nil && subdomainTerms != nil && len(subdomainTerms.Include) == 0) ||
		(subdomainTerms == nil && domainTerms != nil && len(domainTerms.Include) == 0) ||
		(domainTerms != nil && subdomainTerms != nil && len(domainTerms.Include)+len(subdomainTerms.Include) == 0) {
		return nil, &ArgError{"domainTerms/subdomainTerms", "must contain at least one Include term"}
	}

	var request = &domainDiscoveryRequest{
		service.client.apiKey,
		domainTerms,
		subdomainTerms,
		"JSON",
		"",
	}

	for _, opt := range opts {
		opt(request)
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	req, err := service.newRequest(requestBody)
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer

	resp, err := service.client.Do(ctx, req, &b)
	if err != nil {
		return &Response{
			Response: resp,
			Body:     b.Bytes(),
		}, err
	}

	return &Response{
		Response: resp,
		Body:     b.Bytes(),
	}, nil
}

// parse parses raw Domains & Subdomains Discovery API response.
func parse(raw []byte) (*apiResponse, error) {
	var response apiResponse

	err := json.NewDecoder(bytes.NewReader(raw)).Decode(&response)
	if err != nil {
		return nil, fmt.Errorf("cannot parse response: %w", err)
	}

	return &response, nil
}

// Get returns parsed Domains & Subdomains Discovery API response.
func (service domainDiscoveryServiceOp) Get(
	ctx context.Context,
	domainTerms *SearchTerms, subdomainTerms *SearchTerms,
	opts ...Option,
) (domainDiscoveryResponse *DomainDiscoveryResponse, resp *Response, err error) {
	optsJSON := make([]Option, 0, len(opts)+1)
	optsJSON = append(optsJSON, opts...)
	optsJSON = append(optsJSON, OptionOutputFormat("JSON"))

	resp, err = service.request(ctx, domainTerms, subdomainTerms, optsJSON...)
	if err != nil {
		return nil, resp, err
	}

	domainDiscoveryResp, err := parse(resp.Body)
	if err != nil {
		return nil, resp, err
	}

	if domainDiscoveryResp.Message != "" || domainDiscoveryResp.Code != 0 {
		return nil, nil, &ErrorMessage{
			Code:    domainDiscoveryResp.Code,
			Message: domainDiscoveryResp.Message,
		}
	}

	return &domainDiscoveryResp.DomainDiscoveryResponse, resp, nil
}

// GetRaw returns raw Domains & Subdomains Discovery API response as the Response struct with Body saved as a byte slice.
func (service domainDiscoveryServiceOp) GetRaw(
	ctx context.Context,
	domainTerms *SearchTerms, subdomainTerms *SearchTerms,
	opts ...Option,
) (resp *Response, err error) {
	resp, err = service.request(ctx, domainTerms, subdomainTerms, opts...)
	if err != nil {
		return resp, err
	}

	if respErr := checkResponse(resp.Response); respErr != nil {
		return resp, respErr
	}

	return resp, nil
}

// ArgError is the argument error.
type ArgError struct {
	Name    string
	Message string
}

// Error returns error message as a string.
func (a *ArgError) Error() string {
	return `invalid argument: "` + a.Name + `" ` + a.Message
}
