package main

import (
	"bufio"
	"encoding/csv"
	"os"
)

func ReadFileLineByLineAsQueries(filePath string) ([]Query, error) {
	inFile, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(inFile)
	results := make([]Query, 0)
	for scanner.Scan() {
		hostname := scanner.Text()
		q := Query{
			Hostname: hostname,
		}
		results = append(results, q)
	}
	return results, nil
}

func WriteResultsToCSV(header []string, rows [][]string, outfilePath string) error {
	f, err := os.Create(outfilePath)

	if err != nil {
		return err
	}

	w := csv.NewWriter(f)
	defer w.Flush()

	if err = w.Write(header); err != nil {
		return err
	}
	if err = w.WriteAll(rows); err != nil {
		return err
	}
	return nil
}