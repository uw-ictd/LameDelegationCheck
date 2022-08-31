package main

import "github.com/miekg/dns"

func convertQueryTypeStringToDNSType(qType string) uint16 {
	for dnsType, dnsTypeAsString := range dns.TypeToString {
		if dnsTypeAsString == qType {
			return dnsType
		}
	}
	return dns.TypeA  // If query lookup results in a fail, return the dns.TypeA record as default.
}
