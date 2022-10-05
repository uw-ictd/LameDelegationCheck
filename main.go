package main

import (
	"github.com/urfave/cli/v2"
	"log"
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
				Usage: "Query the domain name for lame delegations.",
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
			{
				Name: "scan",
				Aliases: []string{"s"},
				Usage: "Scan the input list of hostnames for lame delegations.",
				Action: ScanHostnames,
				Flags: []cli.Flag {
					&cli.StringFlag{
						Name: "input",
						Aliases: []string{"i"},
						Usage: "Filename / path to file containing hostnames to scan",
						Required: true,
					},
					&cli.StringFlag{
						Name: "queryType",
						Aliases: []string{"t"},
						Usage: "Type of DNS Query to perform. (Default: A)",
						Value: "A",
					},
					&cli.StringFlag{
						Name: "outdir",
						Aliases: []string{"o"},
						Usage: "Name of the output directory to store the scanned results in",
						Value: "results",
					},
				},
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

