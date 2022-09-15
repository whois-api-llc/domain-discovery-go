package example

import (
	"context"
	"errors"
	domaindiscovery "github.com/whois-api-llc/domain-discovery-go"
	"log"
	"time"
)

func GetData(apikey string) {
	client := domaindiscovery.NewBasicClient(apikey)

	// Get parsed Domains & Subdomains Discovery API response by IP address as a model instance.
	domainDiscoveryResp, resp, err := client.Get(context.Background(),
		// specify domain search terms
		&domaindiscovery.SearchTerms{[]string{"amazon.*"}, nil},
		// leave subdomains search terms unspecified, this causes the only domains to be returned
		nil,
		// this option is ignored, as the inner parser works with JSON only
		domaindiscovery.OptionOutputFormat("XML"))

	if err != nil {
		// Handle error message returned by server.
		var apiErr *domaindiscovery.ErrorMessage
		if errors.As(err, &apiErr) {
			log.Println(apiErr.Code)
			log.Println(apiErr.Message)
		}
		log.Fatal(err)
	}

	// Then print all returned domain names.
	for _, domainName := range domainDiscoveryResp.DomainsList {
		log.Println(domainName)
	}

	log.Println("raw response is always in JSON format. Most likely you don't need it.")
	log.Printf("raw response: %s\n", string(resp.Body))
}

func GetRawData(apikey string) {
	client := domaindiscovery.NewBasicClient(apikey)

	// Get raw API response.
	resp, err := client.GetRaw(context.Background(),
		// specify domain and subdomain search terms as separate arguments.
		&domaindiscovery.SearchTerms{Include: []string{"amazon.com"}, Exclude: nil},
		&domaindiscovery.SearchTerms{Include: []string{"aws*"}, Exclude: []string{"*portal*", "*beta*"}},
		// specify the date from which domains/subdomains are discovered
		domaindiscovery.OptionSinceDate(time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)))

	if err != nil {
		// Handle error message returned by server
		log.Fatal(err)
	}

	log.Println(string(resp.Body))
}
