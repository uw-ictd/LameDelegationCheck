package main

import (
	"github.com/miekg/dns"
	"net"
	"strings"
)

func convertQueryTypeStringToDNSType(qType string) uint16 {
	for dnsType, dnsTypeAsString := range dns.TypeToString {
		if dnsTypeAsString == qType {
			return dnsType
		}
	}
	return dns.TypeA  // If query lookup results in a fail, return the dns.TypeA record as default.
}

func computeRecursiveChainLookups(hostname string) []string {
	segments := dns.SplitDomainName(hostname)
	results := make([]string, 0)
	results = append(results, ".")
	for i := len(segments) - 1; i >= 0; i-- {
		splitList := segments[i:len(segments)]
		dn := dns.Fqdn(strings.Join(splitList, "."))
		results = append(results, dn)
	}
	return results
}

func convertDnsNStoNetNS(in []dns.NS) []*net.NS {
	results := make([]*net.NS, 0)
	for _, rr := range in {
		ns := &net.NS{Host: rr.Ns}
		results = append(results, ns)
	}
	return results
}

func convertNetNStoDnsNS(in []*net.NS) []dns.NS {
	results := make([]dns.NS, 0)
	for _, rr := range in {
		ns := dns.NS{
			Ns:  rr.Host,
		}
		results = append(results, ns)
	}
	return results
}