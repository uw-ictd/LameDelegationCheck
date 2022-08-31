package main

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
)

func IdentifyNameServers(domainName string) []*net.NS {
	fqdnQuery := dns.Fqdn(domainName)
	nsList, err := net.LookupNS(fqdnQuery)
	if err != nil {
		fmt.Printf("No name servers found")
		return nil
	}
	return nsList
}
