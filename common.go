// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"sync"
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
}

type programStatus struct {
	probing    *sync.WaitGroup
	errorCount uint32 // only access via sync/atomic while go-routines running
	output     chan<- string
}
