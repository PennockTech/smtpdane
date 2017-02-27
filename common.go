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
	defaultPort      string
	defaultPortInt   int
	tlsOnConnect     bool
	showVersion      bool
	heloName         string
	mxLookup         bool
	submissionLookup bool
	srvTCPLookup     string
	noColor          bool
	noCertNames      bool
	akaNames         akaHostList
	connectTimeout   time.Duration
	onlyIPv4         bool
	onlyIPv6         bool
}

type programStatus struct {
	probing    *sync.WaitGroup
	errorCount uint32 // only access via sync/atomic while go-routines running
	output     chan<- string
}

type akaHostList []string

func (a *akaHostList) Set(s string) error { *a = append(*a, s); return nil }
func (a *akaHostList) String() string     { return strings.Join(*a, " ") }
