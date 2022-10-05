package main

import (
	"crypto/rand"
	"github.com/miekg/dns"
	"math/big"
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

func makeDNSQuery(name string, queryType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), queryType)
	msg.Id = dns.Id()
	return msg
}

func generateRandomString(size int) string {
	const universe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	s := make([]byte, size)
	for i := 0; i < size; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(universe))))
		if err != nil {
			return ""
		}
		s[i] = universe[n.Int64()]
	}
	return string(s)
}

func Keys(m map[int]int) []int {
	r := make([]int, 0, len(m))
	for k := range m {
		r = append(r, k)
	}
	return r
}
