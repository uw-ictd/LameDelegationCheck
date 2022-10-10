package main

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"strconv"
)

func findDelegations(res *dns.Msg) ([]dns.NS, bool) {
	containsDelegations := len(res.Ns) > 0
	isAnswer := false
	if !containsDelegations {
		// Check if it contains answers which are NS entries
		containsAnswers := len(res.Answer) > 0
		if !containsAnswers {
			return nil, isAnswer
		}
		isAnswer = true
		res.Ns = res.Answer
	}
	nameservers := res.Ns
	results := make([]dns.NS, 0)
	for _, nsEntry := range nameservers {
		switch t := nsEntry.(type) {
		case *dns.NS:
			results = append(results, *t)
		case *dns.SOA:
			isAnswer = true
		}
	}
	return results, isAnswer
}

func checkResponseContentContains(res *dns.Msg, queryType uint16) bool {
	authorityRRSet := res.Ns
	answerRRSet := res.Answer

	if len(authorityRRSet) > 0 || len(answerRRSet) > 0 {
		for _, rrSet := range [][]dns.RR{authorityRRSet, answerRRSet} {
			for _, rr := range rrSet {
				if rr.Header().Rrtype == queryType {
					return true
				}
			}
		}
	}

	return false
}

func compareDelegationCorrectness(m map[string][]dns.NS, shouldLog bool) (bool, []dns.NS, error) {
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
			return false, nil, PrepareError(MinNameServerRequirementFailed, strconv.FormatInt(int64(n), 10))
		}
		if shouldLog {
			fmt.Printf("Number of delegated nameservers : %v by %v parent Nameservers\n", n, p)
		}
	}
	results := make([]dns.NS, 0)
	for ns, _ := range nsMap {
		results = append(results, ns)
	}
	if len(resMap) == 1 {
		return true, results, nil
	}
	data, _ := json.Marshal(Keys(resMap))
	return false, nil, PrepareError(IncorrectDelegations, string(data))
}
