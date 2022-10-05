package main

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
)

func IdentifyNameServers(domainName string, shouldLog bool) ([]*net.NS, error) {
	fqdnQuery := dns.Fqdn(domainName)
	nsList, err := net.LookupNS(fqdnQuery)
	if err != nil {
		if shouldLog {
			fmt.Printf("No name servers found. %v\n", err)
		}
		return nil, PrepareError(NoNameServersFound, fqdnQuery)
	}
	return nsList, nil
}
