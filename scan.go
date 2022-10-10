package main

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	ResultPrefix = "result"
	RandomStringSize = 6
)

func sanitizeAndPrepare(input string, queryType string, outputDir string) (uint16, string, error) {
	fmt.Printf("Input file: %v\n", input)
	fmt.Printf("Output file: %v\n", outputDir)
	fmt.Printf("DNS Query Type: %v\n", queryType)

	if _, err := os.Stat(input); os.IsNotExist(err) {
		return 0, "", err
	}

	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		return 0, "", err
	}

	outputFileName := fmt.Sprintf("%v-%v-%v.csv",
		ResultPrefix,
		generateRandomString(RandomStringSize),
		time.Now().Unix(),
	)

	outputLocation := filepath.Join(outputDir, outputFileName)

	dnsQueryType := convertQueryTypeStringToDNSType(queryType)
	return dnsQueryType, outputLocation, nil
}

func ScanHostnames(ctx *cli.Context) error {
	inputFilePath := ctx.String("input")
	dnsQueryTypeString := ctx.String("queryType")
	outputDirPath := ctx.String("outdir")

	dnsQueryType, outputFilePath, err := sanitizeAndPrepare(inputFilePath, dnsQueryTypeString, outputDirPath)
	if err != nil {
		return err
	}
	fmt.Printf("DNS Query Type: %v\n", dnsQueryType)
	fmt.Printf("Output file stored at: %v\n", outputFilePath)

	queries, err := ReadFileLineByLineAsQueries(inputFilePath, dnsQueryType)
	if err != nil {
		return err
	}
	fmt.Printf("Total queries: %v\n", len(queries))

	numThreads := runtime.NumCPU() * 4

	tasks := make(chan Query, len(queries))
	promiseResponses := make(chan Result, len(queries))
	results := make([]Result, 0)

	// Spin up workers.
	for workerIndex := 0; workerIndex < numThreads; workerIndex++ {
		go ScanWorker(workerIndex, tasks, promiseResponses)
	}

	// Schedule the jobs.
	for jobIndex := 0; jobIndex < len(queries); jobIndex++ {
		tasks <- queries[jobIndex]
	}

	// Wait for result futures to be retrieved
	for resultIndex := 0; resultIndex < len(queries); resultIndex++ {
		r := <- promiseResponses
		if resultIndex % 10 == 0 {
			fmt.Printf("Received %v/%v responses\n", resultIndex, len(queries))
		}
		results = append(results, r)
	}

	header := GetResultRowHeader()
	rows := make([][]string, 0)
	for _, res := range results {
		rows = append(rows, res.SerializeAsRow())
	}

	close(tasks)
	close(promiseResponses)

	_ = WriteResultsToCSV(header, rows, outputFilePath)
	return nil
}