package main

import (
	"errors"
	"fmt"
)

const (
	NoNameServersFound = "no name servers found [%v]"
	NoNameServerResponse = "name server [%v] failed to respond"
	MinNameServerRequirementFailed = "at least two name servers are needed - found [%v]"
	IncorrectDelegations = "delegations from name servers do not match - found [%v]"
	NameserverResponseNotAuthoritative = "name server [%v] response not authoritative"
)

func PrepareError(errorMessage string, blob ...string) error {
	return errors.New(fmt.Sprintf(errorMessage, blob))
}