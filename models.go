package domaindiscovery

import (
	"fmt"
)

// SearchTerms is a set of included and excluded search terms.
type SearchTerms struct {
	// Include is an array of included search terms. Maximum 4 items. Case insensitive.
	Include []string `json:"include,omitempty"`

	// Exclude is an array of excluded search terms. Maximum 4 items. Case insensitive.
	Exclude []string `json:"exclude,omitempty"`
}

// domainDiscoveryRequest is the request struct for Domains & Subdomains Discovery API.
type domainDiscoveryRequest struct {
	// APIKey is the user's API key.
	APIKey string `json:"apiKey"`

	// Domains is the domains search terms.
	Domains *SearchTerms `json:"domains,omitempty"`

	// Subdomains is the subdomains search terms.
	Subdomains *SearchTerms `json:"subdomains,omitempty"`

	// OutputFormat is the response output format JSON | XML.
	OutputFormat string `json:"outputFormat,omitempty"`

	// SinceDate If present, search through domains/subdomains discovered since the given date.
	SinceDate string `json:"sinceDate,omitempty"`
}

// DomainDiscoveryResponse is a response of Domains & Subdomains Discovery API.
type DomainDiscoveryResponse struct {
	// DomainsList is the list of domains matching the criteria.
	DomainsList []string `json:"domainsList"`

	// DomainsCount is the number of domains matching the criteria.
	DomainsCount int `json:"domainsCount"`
}

// ErrorMessage is the error message.
type ErrorMessage struct {
	Code    int    `json:"code"`
	Message string `json:"messages"`
}

// Error returns error message as a string.
func (e *ErrorMessage) Error() string {
	return fmt.Sprintf("API error: [%d] %s", e.Code, e.Message)
}
