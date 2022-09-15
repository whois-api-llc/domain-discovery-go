[![domain-discovery-go license](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![domain-discovery-go made-with-Go](https://img.shields.io/badge/Made%20with-Go-1f425f.svg)](https://pkg.go.dev/github.com/whois-api-llc/domain-discovery-go)
[![domain-discovery-go test](https://github.com/whois-api-llc/domain-discovery-go/workflows/Test/badge.svg)](https://github.com/whois-api-llc/domain-discovery-go/actions/)

# Overview

The client library for
[Domains & Subdomains Discovery API](https://domains-subdomains-discovery.whoisxmlapi.com/)
in Go language.

The minimum go version is 1.17.

# Installation

The library is distributed as a Go module

```bash
go get github.com/whois-api-llc/domain-discovery-go
```

# Examples

Full API documentation available [here](https://domains-subdomains-discovery.whoisxmlapi.com/api/documentation/making-requests)

You can find all examples in `example` directory.

## Create a new client

To start making requests you need the API Key. 
You can find it on your profile page on [whoisxmlapi.com](https://whoisxmlapi.com/).
Using the API Key you can create Client.

Most users will be fine with `NewBasicClient` function. 
```go
client := domaindiscovery.NewBasicClient(apiKey)
```

If you want to set custom `http.Client` to use proxy then you can use `NewClient` function.
```go
transport := &http.Transport{Proxy: http.ProxyURL(proxyUrl)}

client := domaindiscovery.NewClient(apiKey, domaindiscovery.ClientParams{
    HTTPClient: &http.Client{
        Transport: transport,
        Timeout:   20 * time.Second,
    },
})
```

## Make basic requests

Domains & Subdomains Discovery API lets you find domains and subdomains related by specific terms in their hostnames.

```go

// Make request to get a list of all domains matching the criteria without subdomains.
domainDiscoveryResp, resp, err := client.Get(ctx,
    &domaindiscovery.SearchTerms{[]string{"amazon.*"}, nil},
    nil)

for _, domainName := range domainDiscoveryResp.DomainsList {
    log.Println(domainName)
}


// Make request to get only subdomains matching the criteria.
domainDiscoveryResp, resp, err := client.Get(ctx,
    nil,
    &domaindiscovery.SearchTerms{[]string{"adidas*"}, []string{"*shoes*"}})

log.Println(domainDiscoveryResp.DomainsCount)


// Make request to get raw data in XML.
resp, err := client.GetRaw(ctx,
    &domaindiscovery.SearchTerms{Include: []string{"amazon.com"}, Exclude: nil},
    &domaindiscovery.SearchTerms{Include: []string{"aws*"}, Exclude: []string{"*portal*", "*beta*"}},
    domaindiscovery.OptionOutputFormat("XML"))

log.Println(string(resp.Body))

```
