// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

// We are canonically imported from go.pennock.tech/fingerd but because we are
// not a library, we do not apply this as an import constraint on the package
// declarations.  You can fork and build elsewhere more easily this way, while
// still getting dependencies without a dependency manager in play.
//
// This comment is just to let you know that the canonical import path is
// go.pennock.tech/fingerd and not now, nor ever, using DNS pointing to a
// code-hosting site not under our direct control.  We keep our options open,
// for moving where we keep the code publicly available.

// +build go1.8

package main

import (
	"flag"
	"fmt"
	"os"
	"sync"
	"time"
)

func init() {
	flag.BoolVar(&opts.showVersion, "version", false, "show version and exit")
	flag.BoolVar(&opts.quiet, "quiet", false, "be quiet unless there's a failure")
	flag.BoolVar(&opts.debug, "debug", false, "show debugging output; may be unpretty")
	flag.BoolVar(&opts.debugFast, "debug-fast", false, "bypass batching controls for quiet")
	flag.BoolVar(&opts.noColor, "nocolor", false, "inhibit color output")

	flag.StringVar(&opts.defaultPort, "port", "smtp(25)", "port to connect to")
	flag.BoolVar(&opts.tlsOnConnect, "tls-on-connect", false, "start TLS immediately upon connection")
	flag.DurationVar(&opts.connectTimeout, "connect-timeout", 10*time.Second, "timeout for SMTP connection establishment")
	flag.StringVar(&opts.heloName, "helo", "smtpdane.invalid", "name to send in HELO/EHLO")
	flag.Var(&opts.akaNames, "aka", "add this also-known-as for all cert validations")
	flag.BoolVar(&opts.noCertNames, "nocertnames", false, "inhibit loading certs to name TLSA records")
	flag.BoolVar(&opts.showCertInfo, "show-cert-info", false, "show information about certs")
	flag.BoolVar(&opts.showCerts, "showcerts", false, "show PEM of certificates seen") // named to match s_client(1)
	flag.DurationVar(&opts.expirationWarning, "expiration-warning", 168*time.Hour, "error if cert in chain this close to expiring")
	flag.BoolVar(&opts.expectOCSP, "expect-ocsp", false, "treat missing OCSP as an error")

	flag.BoolVar(&opts.terse, "terse", false, "terse output")
	flag.BoolVar(&opts.forNagios, "nagios", false, "format output as NAGIOS plugin")

	// Mutually exclusive groups

	flag.BoolVar(&opts.mxLookup, "mx", false, "arguments are domains, lookup MX records")
	flag.BoolVar(&opts.submissionLookup, "submission", false, "arguments are domains, lookup submission SRV records")
	flag.BoolVar(&opts.submissionsLookup, "submissions", false, "arguments are domains, lookup submissions SRV records & auto-enable -tls-on-connect")
	flag.StringVar(&opts.srvTCPLookup, "srv", "", "arguments are domains, lookup this TCP SRV record")

	flag.BoolVar(&opts.onlyIPv4, "4", false, "only probe IPv4 addresses")
	flag.BoolVar(&opts.onlyIPv6, "6", false, "only probe IPv6 addresses")

	// Aliases
	flag.BoolVar(&opts.quiet, "q", false, "be quiet unless there's a failure")
	flag.StringVar(&opts.defaultPort, "p", "smtp(25)", "port to connect to")
}

func checkFlagsForConflicting() bool {
	out := os.Stderr
	if opts.forNagios {
		out = os.Stdout
	}

	if opts.mxLookup && (opts.submissionLookup || opts.submissionsLookup) {
		fmt.Fprintf(out, "%s: -mx and -submission(s) conflict\n", os.Args[0])
		return true
	}
	if opts.submissionLookup && opts.submissionsLookup {
		fmt.Fprintf(out, "%s: -submission and -submissions conflict\n", os.Args[0])
		return true
	}
	if opts.mxLookup && opts.srvTCPLookup != "" {
		fmt.Fprintf(out, "%s: -mx and -srv SRV conflict\n", os.Args[0])
		return true
	}
	if opts.submissionLookup && opts.srvTCPLookup != "" {
		fmt.Fprintf(out, "%s: -submission and -srv SRV conflict\n", os.Args[0])
		return true
	}

	if opts.onlyIPv4 && opts.onlyIPv6 {
		fmt.Fprintf(out, "%s: -4 and -6 conflict\n", os.Args[0])
		return true
	}

	return false
}

func main() {
	// We don't hard-code the Nagios exit codes, in case other systems want
	// something different.
	flag.Parse()

	exitBadFlags := 1
	exitServerWarnings := 1
	exitServerErrors := 1
	exitOK := 0
	errOutStream := os.Stderr

	if opts.forNagios {
		opts.terse = true
		opts.noColor = true
		exitBadFlags = 3
		exitServerErrors = 2
		exitServerWarnings = 1
		errOutStream = os.Stdout
	}
	if opts.submissionsLookup {
		opts.tlsOnConnect = true
	}

	if opts.showVersion {
		version()
		if opts.forNagios {
			// strictly, incompatible; nagios takes precedence, we're not OK
			os.Exit(exitBadFlags)
		}
		return
	}
	if checkFlagsForConflicting() {
		os.Exit(exitBadFlags)
	}
	if !opts.noCertNames {
		initCertNames()
	}

	hostlist := flag.Args()
	if len(hostlist) == 0 {
		flag.Usage()
		os.Exit(exitBadFlags)
	}

	dp, err := PortParse(opts.defaultPort)
	if err != nil {
		fmt.Fprintf(errOutStream, "%s: can't parse %q: %s\n", os.Args[0], opts.defaultPort, err)
		os.Exit(exitBadFlags)
	}
	opts.defaultPortInt = dp

	messages := make(chan string, 10)
	shuttingDown := &sync.WaitGroup{}
	go emitOutputMessages(messages, shuttingDown)

	status := &programStatus{
		probing:       &sync.WaitGroup{},
		batchChildren: &sync.WaitGroup{},
		shuttingDown:  shuttingDown,
		output:        messages,
	}

	for _, hostSpec := range hostlist {
		status.probing.Add(1)
		if opts.mxLookup {
			go probeMX(hostSpec, status)
		} else if opts.submissionLookup {
			go probeSRV("submission", hostSpec, status)
		} else if opts.submissionsLookup {
			go probeSRV("submissions", hostSpec, status)
		} else if opts.srvTCPLookup != "" {
			go probeSRV(opts.srvTCPLookup, hostSpec, status)
		} else {
			status.probing.Done() // the ..Go wrapper bumps it again
			probeHostGo(hostSpec, status)
		}
	}

	debugf("main: waiting for probing to finish\n")
	status.probing.Wait()
	debugf("main: shutting down\n")
	shuttingDown.Add(1)

	// Every other user of BatchFinished wants it to decr probing too (else
	// every other caller did an anon func for defer, doing a probing.Done()
	// and then BatchFinished) so I moved a probing.Done() in there and
	// simplified the defers.  Price: we need to re-bump probing here.
	status.probing.Add(1)
	status.BatchFinished()

	shuttingDown.Wait()

	if status.errorCount != 0 {
		fmt.Fprintf(errOutStream, "%s: encountered %d errors\n", os.Args[0], status.errorCount)
	}
	if status.warningCount != 0 {
		fmt.Fprintf(errOutStream, "%s: encountered %d warnings\n", os.Args[0], status.warningCount)
	}
	if status.warningCount != 0 && status.errorCount == 0 {
		os.Exit(exitServerWarnings)
	} else if status.errorCount != 0 {
		os.Exit(exitServerErrors)
	}

	os.Exit(exitOK)
}
