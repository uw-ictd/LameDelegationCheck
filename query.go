package main

import (
	"context"
	"fmt"
	"github.com/allegro/bigcache/v3"
	"github.com/miekg/dns"
	"github.com/urfave/cli/v2"
	"net"
	"strconv"
	"time"
)

type Query struct {
	Hostname string
	QueryType uint16
}

type Result struct {
	Hostname string
	ContainsLameDelegation bool
	Error error
}

func GetResultRowHeader() []string {
	row := make([]string, 0)
	row = append(row, "Hostname")
	row = append(row, "ContainsLameDelegation")
	row = append(row, "Error")
	return row
}

func (r *Result) SerializeAsRow() []string {
	row := make([]string, 0)
	row = append(row, r.Hostname)
	row = append(row, strconv.FormatBool(r.ContainsLameDelegation))
	if r.Error != nil {
		row = append(row, r.Error.Error())
	} else {
		row = append(row, "")
	}
	return row
}

func ProcessQuery(queries []Query, cache *bigcache.BigCache, shouldLog bool) []Result {
	results := make([]Result, 0)
	for _, query := range queries {
		result := Result{Hostname: query.Hostname}

		if shouldLog {
			fmt.Printf("Querying %v for %v\n", query.Hostname, query.QueryType)
		}

		re := computeRecursiveChainLookups(query.Hostname)

		if shouldLog {
			fmt.Printf("%v\n", re)
		}

		var delegatedChildNSRecords []dns.NS
		var authorityDelegatedNSRecords []dns.NS
		var correctlyDelegated bool
		var nameservers []*net.NS
		var currentZoneDelegatedNameServers []byte  // for cache-hit
		var err error

		for i := 1; i < len(re); i++ {
			parent := re[i-1]
			currentZone := re[i]
			if shouldLog {
				fmt.Printf("Finding NS for the parent %v\n", parent)
			}
			if nameservers == nil {
				if shouldLog {
					fmt.Printf("Updating NS\n")
				}
				nameserverBytes, err := cache.Get(parent)
				if err != nil {
					nameservers, err = IdentifyNameServers(parent, shouldLog)
					if err != nil {
						result.Error = err
					}
					//fmt.Printf("Insert cache: [%v] --> [%v]\n", parent, string(NetNStoCacheValueBytes(nameservers)))
					_ = cache.Set(parent, NetNStoCacheValueBytes(nameservers))
				} else {
					//fmt.Printf("HIT cache: [%v] --> [%v]\n", parent, string(nameserverBytes))
					nameservers = NetNSBytestoNetNS(nameserverBytes)
				}
			}
			// Check if current zone needs a lookup?
			currentZoneDelegatedNameServers, err = cache.Get(currentZone)
			if err != nil {
				// Not found in cache, perform the necessary queries.
				nsQuery := makeDNSQuery(currentZone, dns.TypeNS)
				parentDelegations := make(map[string][]dns.NS)
				for _, parentNS := range nameservers {
					if shouldLog {
						fmt.Printf("Asking %v for NS records for %v\n", parentNS.Host, currentZone)
					}

					ctx, cancel := context.WithTimeout(context.Background(), time.Second * 30)
					defer cancel()

					res, err := dns.ExchangeContext(ctx, nsQuery, net.JoinHostPort(parentNS.Host, "53"))
					if err != nil || !checkResponseContentContains(res, dns.TypeNS) {
						if shouldLog {
							fmt.Printf("\tReceived no response from %v with error: %v\n", parent, err)
						}
						if err != nil {
							result.Error = PrepareError(NoNameServerResponse, net.JoinHostPort(parentNS.Host, "53"), err.Error())
						} else {
							result.Error = PrepareError(NoNameServersFound, net.JoinHostPort(parentNS.Host, "53"))
						}
						result.ContainsLameDelegation = true
						continue
					}
					delegations, isAnswer := findDelegations(res)
					if shouldLog {
						for _, answer := range res.Answer {
							fmt.Printf("\t\tAnswer: %v\n", answer)
						}
					}
					parentDelegations[parentNS.Host] = delegations
					if isAnswer {
						authorityDelegatedNSRecords = convertNetNStoDnsNS(nameservers)
					}
				}
				// Check that all parents have the same delegations available
				correctlyDelegated, delegatedChildNSRecords, err = compareDelegationCorrectness(parentDelegations, shouldLog)
				if delegatedChildNSRecords == nil && correctlyDelegated == false {
					if authorityDelegatedNSRecords != nil {
						delegatedChildNSRecords = authorityDelegatedNSRecords
						correctlyDelegated = true
					}
				}
				if err != nil {
					result.Error = err
					result.ContainsLameDelegation = true
					break
				}
				nameservers = convertDnsNStoNetNS(delegatedChildNSRecords)
				if correctlyDelegated && dns.Fqdn(currentZone) != dns.Fqdn(query.Hostname) {
					//fmt.Printf("Insert cache: [%v] == [%v] --> [%v]\n", currentZone, query.Hostname, string(NetNStoCacheValueBytes(nameservers)))
					_ = cache.Set(currentZone, NetNStoCacheValueBytes(nameservers))
				}
			} else {
				//fmt.Printf("HIT cache: [%v] --> [%v]\n", currentZone, string(currentZoneDelegatedNameServers))
				nameservers = NetNSBytestoNetNS(currentZoneDelegatedNameServers)
				delegatedChildNSRecords = convertNetNStoDnsNS(nameservers)
				correctlyDelegated = true // Since it's a cache hit.
			}

			if shouldLog {
				fmt.Printf("%v delegations from %v are %v\n", currentZone, parent, correctlyDelegated)
			}
			if !correctlyDelegated {
				//return errors.New("contains lame delegation at the nameservers")
				result.Error = err
				break
			}
		}
		// Perform the final set of queries for the actual query type lameness.
		var containsLameDelegations bool
		for _, ns := range delegatedChildNSRecords {
			if shouldLog {
				fmt.Printf("Asking %v for %v (%v) type\n", ns.Ns, query.Hostname, query.QueryType)
			}
			dnsQuery := makeDNSQuery(query.Hostname, query.QueryType)

			ctx, cancel := context.WithTimeout(context.Background(), time.Second * 30)
			defer cancel()

			res, err := dns.ExchangeContext(ctx, dnsQuery, net.JoinHostPort(ns.Ns, "53"))
			if err != nil || res.Authoritative == false {
				if err != nil {
					if shouldLog {
						fmt.Printf("\t%v Failed to lookup response. Error: %v, %v\n", Yellow, err, Reset)
					}
					result.Error = PrepareError(NoNameServerResponse, net.JoinHostPort(ns.Ns, "53"), err.Error())
				} else {
					if shouldLog {
						fmt.Printf("\t%v Failed to lookup response. Error: %v, Authoritative?: %v%v\n", Yellow, err, res.Authoritative, Reset)
					}
					result.Error = PrepareError(NameserverResponseNotAuthoritative, net.JoinHostPort(ns.Ns, "53"))
				}
				containsLameDelegations = true
				result.ContainsLameDelegation = containsLameDelegations
				continue
			}
			if shouldLog {
				for _, answer := range res.Answer {
					fmt.Printf("\t\tAnswer: %v\n", answer)
				}
			}
		}
		if !containsLameDelegations {
			if shouldLog {
				fmt.Printf("%vContains no lame delegations%v\n", Green, Reset)
			}
			result.ContainsLameDelegation = false
		} else {
			if shouldLog {
				fmt.Printf("%vContains lame delegations%v\n", Red, Reset)
			}
			result.ContainsLameDelegation = true
		}
		results = append(results, result)
	}
	return results
}

func QueryDomain(ctx *cli.Context) error {
	domainName := ctx.String("domain")
	dnsQueryTypeString := ctx.String("queryType")
	dnsQueryType := convertQueryTypeStringToDNSType(dnsQueryTypeString)

	cache := NewCache()

	query := Query{Hostname: domainName, QueryType: dnsQueryType}
	_ = ProcessQuery([]Query{query}, cache,true)

	return nil
}
