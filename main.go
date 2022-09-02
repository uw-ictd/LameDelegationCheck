package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/urfave/cli/v2"
	"log"
	"net"
	"os"
)

const (
	Red = "\033[31m"
	Green = "\033[32m"
	Yellow = "\033[33m"
	Reset = "\033[0m"
)

func main() {
	app := &cli.App{
		Name:  "lame-delegation-check",
		Usage: "Identify if a domain name contains any lame delegations",
		Commands: []*cli.Command{
			{
				Name: "query",
				Aliases: []string{"q"},
				Usage: "Query the domain name for name delegations.",
				Action: QueryDomain,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: "domain",
						Aliases: []string{"d"},
						Usage: "Domain name to check for lame delegations",
						Required: true,
					},
					&cli.StringFlag{
						Name: "queryType",
						Aliases: []string{"t"},
						Usage: "Type of DNS Query to perform. (Default: A)",
						Value: "A",
					},
				},
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func findDelegations(res *dns.Msg) []dns.NS {
	containsDelegations := len(res.Ns) > 0
	if !containsDelegations {
		// Check if it contains answers which are NS entries
		containsAnswers := len(res.Answer) > 0
		if !containsAnswers {
			return nil
		}
		res.Ns = res.Answer
	}
	nameservers := res.Ns
	results := make([]dns.NS, 0)
	for _, nsEntry := range nameservers {
		switch t := nsEntry.(type) {
		case *dns.NS:
			results = append(results, *t)
		}
	}
	return results
}

func compareDelegationCorrectness(m map[string][]dns.NS) (bool, []dns.NS) {
	// TODO: Perform a cleaner check, for now the assumption is the length of entries.
	resMap := make(map[int]int)
	nsMap := make(map[dns.NS]bool)
	for _, delegatedEntries := range m {
		nEntries := len(delegatedEntries)
		if _, ok := resMap[nEntries]; ok {
			resMap[nEntries]++
		} else {
			resMap[nEntries] = 1
		}
		for _, nsEntry := range delegatedEntries {
			nsMap[nsEntry] = true
		}
	}
	// all servers should return the same delegations.
	for n, p := range resMap {
		// There should be at-least two NameServers for safety reasons.
		if n < 2 {
			return false, nil
		}
		fmt.Printf("Number of delegated nameservers : %v by %v parent Nameservers\n", n, p)
	}
	results := make([]dns.NS, 0)
	for ns, _ := range nsMap {
		results = append(results, ns)
	}
	if len(resMap) == 1 {
		return true, results
	}
	return false, nil
}

func QueryDomain(ctx *cli.Context) error {
	domainName := ctx.String("domain")
	dnsQueryTypeString := ctx.String("queryType")
	dnsQueryType := convertQueryTypeStringToDNSType(dnsQueryTypeString)

	fmt.Printf("Querying %v for %v (%v)\n", domainName, dnsQueryTypeString, dnsQueryType)

	re := computeRecursiveChainLookups(domainName)
	fmt.Printf("%v\n", re)

	var delegatedChildNSRecords []dns.NS
	var correctlyDelegated bool

	for i := 1; i < len(re); i++ {
		parent := re[i-1]
		currentZone := re[i]
		fmt.Printf("Finding NS for the parent %v\n", parent)
		nameservers := IdentifyNameServers(parent)
		//for _, ns := range nameservers {
		//	fmt.Printf("\t[%v]\tNS: %v\n", parent, ns.Host)
		//}
		nsQuery := makeDNSQuery(currentZone, dns.TypeNS)
		parentDelegations := make(map[string][]dns.NS)
		for _, parentNS := range nameservers {
			fmt.Printf("Asking %v for NS records for %v\n", parentNS.Host, currentZone)
			res, err := dns.ExchangeContext(context.Background(), nsQuery, net.JoinHostPort(parentNS.Host, "53"))
			if err != nil {
				fmt.Printf("\tReceived no response from %v with error: %v\n", parent, err)
			}
			delegations := findDelegations(res)
			for _, answer := range res.Answer {
				fmt.Printf("\t\tAnswer: %v\n", answer)
			}
			parentDelegations[parentNS.Host] = delegations
		}
		// Check that all parents have the same delegations available
		correctlyDelegated, delegatedChildNSRecords = compareDelegationCorrectness(parentDelegations)
		fmt.Printf("%v delegations from %v are %v\n", currentZone, parent, correctlyDelegated)
		if !correctlyDelegated {
			return errors.New("contains lame delegation at the nameservers")
		}
	}
	// Perform the final set of queries for the actual query type lameness.
	var containsLameDelegations bool
	for _, ns := range delegatedChildNSRecords {
		fmt.Printf("Asking %v for %v (%v) type\n", ns.Ns, domainName, dnsQueryType)
		dnsQuery := makeDNSQuery(domainName, dnsQueryType)
		res, err := dns.ExchangeContext(context.Background(), dnsQuery, net.JoinHostPort(ns.Ns, "53"))
		if err != nil || res.Authoritative == false {
			if err != nil {
				fmt.Printf("\t%v Failed to lookup response. Error: %v, %v\n", Yellow, err, Reset)
			} else {
				fmt.Printf("\t%v Failed to lookup response. Error: %v, Authoritative?: %v%v\n", Yellow, err, res.Authoritative, Reset)
			}
			containsLameDelegations = true
			continue
		}
		for _, answer := range res.Answer {
			fmt.Printf("\t\tAnswer: %v\n", answer)
		}
	}
	if !containsLameDelegations {
		fmt.Printf("%vContains no lame delegations%v\n", Green, Reset)
	} else {
		fmt.Printf("%vContains lame delegations%v\n", Red, Reset)
	}

	return nil
}

func makeDNSQuery(name string, queryType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), queryType)
	msg.Id = dns.Id()
	return msg
}
