package main

import (
	"context"
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

func QueryDomain(ctx *cli.Context) error {
	domainName := ctx.String("domain")
	dnsQueryTypeString := ctx.String("queryType")
	dnsQueryType := convertQueryTypeStringToDNSType(dnsQueryTypeString)

	fmt.Printf("Querying %v for %v (%v)\n", domainName, dnsQueryTypeString, dnsQueryType)

	ns := IdentifyNameServers(domainName)
	containsLameDelegation := false
	for _, nsEntry := range ns {
		fmt.Printf("\tNS : %v\n", nsEntry.Host)
		dnsQuery := makeDNSQuery(domainName, dnsQueryType)
		res, err := dns.ExchangeContext(context.Background(), dnsQuery, net.JoinHostPort(nsEntry.Host, "53"))
		if err != nil || res.Authoritative == false {
			fmt.Printf("\t%vFailed to lookup IP. Error: %v%v\n", err, Yellow, Reset)
			containsLameDelegation = true
			break
		}
		for _, answer := range res.Answer {
			fmt.Printf("\t\tAnswer: %v\n", answer)
		}
	}
	if containsLameDelegation {
		fmt.Printf("%vContains a lame delegation.%v\n", Red, Reset)
	}
	return nil
}

func makeDNSQuery(name string, queryType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), queryType)
	msg.Id = dns.Id()
	return msg
}
