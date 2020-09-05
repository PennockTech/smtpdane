// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

// This file does not have build-tag constraints, and should build fine on
// versions of Go before 1.8; the goal is that non-Go-programmers who use `go
// get` with an old Go should get one simple message, not drowned out in noise
// of other errors, saying clearly that their Go is too old.
//
// Otherwise, this stuff would all be in main.go

package main

import (
	"strings"
	"sync"
	"time"
)

var opts struct {
	akaNames          akaHostList
	connectTimeout    time.Duration
	debug             bool
	debugFast         bool
	defaultPort       string
	defaultPortInt    int
	expectOCSP        bool
	expirationWarning time.Duration
	forNagios         bool
	heloName          string
	mxLookup          bool
	noCertNames       bool
	noColor           bool
	onlyIPv4          bool
	onlyIPv6          bool
	quiet             bool
	showCertInfo      bool
	showCerts         bool
	showVersion       bool
	srvTCPLookup      string
	submissionLookup  bool
	submissionsLookup bool
	terse             bool
	tlsOnConnect      bool
}

type programStatus struct {
	probing       *sync.WaitGroup
	shuttingDown  *sync.WaitGroup
	batchChildren *sync.WaitGroup
	errorCount    uint32 // must only access via sync/atomic while go-routines running
	warningCount  uint32
	output        chan<- string
	label         string
}

type akaHostList []string

func (a *akaHostList) Set(s string) error { *a = append(*a, s); return nil }
func (a *akaHostList) String() string     { return strings.Join(*a, " ") }
