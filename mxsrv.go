// Copyright © 2017,2018 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

//go:build go1.8

package main

import (
	"fmt"
	"net"
	"strconv"

	"go.pennock.tech/smtpdane/internal/errorlist"
)

// probeMX is the top-level function of a go-routine, much like probeHost,
// but is not responsible for probing any specific SMTP connections; instead
// it should spin up checks for each hostname which we care about
//
// We allow ports on domains; we still lookup MX records, but override port 25
// with the supplied port.
func probeMX(domainSpec string, status *programStatus) {
	status = status.ChildBatcher("probeMX", domainSpec)
	defer status.BatchFinished()

	domain, port, err := HostnameMaybePortFrom(domainSpec)
	if err != nil {
		status.Errorf("error parsing %q: %s", domainSpec, err)
		return
	}

	tieredResults, mxCount, err := ResolveMXTiers(domain)
	if err != nil {
		switch e := err.(type) {
		case *errorlist.List:
			status.Errorf("error resolving MX %q:\n%s", domain, e.FmtIndented())
		default:
			status.Errorf("error resolving MX %q: %s", domain, err)
		}
		return
	}

	status.Wafflef("found %d MX records for %q across %d preference levels", mxCount, domain, len(tieredResults))
	// MX returns DNS label sequences for hostnames, so by definition each is already IsFqdn(),
	// so no need to check before looking for TLSA records, etc.

	seen := make(map[string]struct{}, mxCount)
	for i := range tieredResults {
		status.Wafflef("  %q MX preference %d: %v", domain, tieredResults[i].Preference, tieredResults[i].Hostnames)
		for _, hn := range tieredResults[i].Hostnames {
			if _, already := seen[hn]; already {
				status.Messagef("skipping dup MX hostname: %q", hn)
				continue
			}
			seen[hn] = struct{}{}
			if port != "" {
				hn = net.JoinHostPort(hn, port)
			}
			probeHostGo(hn, status, domain)
		}
	}
}

// probeSRV the top-level function of a go-routine, much like probeHost,
// but is not responsible for probing any specific SMTP connections; instead
// it should spin up checks for each hostname which we care about
//
// We allow ports on domains; we still lookup SRV records, but override the
// port therein with the supplied port.
func probeSRV(srvName, domainSpec string, status *programStatus) {
	domain, port, err := HostnameMaybePortFrom(domainSpec)
	if err != nil {
		status.Errorf("error parsing %q: %s", domainSpec, err)
		status.probing.Done()
		return
	}

	lookup := fmt.Sprintf("_%s._tcp.%s", srvName, domain)
	status = status.ChildBatcher("probeSRV", lookup)
	defer status.BatchFinished()

	srvList, err := ResolveSRV(lookup)
	if err != nil {
		switch e := err.(type) {
		case *errorlist.List:
			status.Errorf("error resolving SRV %q:\n%s", lookup, e.FmtIndented())
		default:
			status.Errorf("error resolving SRV %q: %s", lookup, err)
		}
		return
	}

	status.Wafflef("found %d SRV records for %q: %v", len(srvList), lookup, srvList)
	// SRV returns DNS label sequences for hostnames, so by definition each is already IsFqdn(),
	// so no need to check before looking for TLSA records, etc.

	seen := make(map[string]struct{}, len(srvList))
	for _, srv := range srvList {
		// There might be two different ports in SRV, but if we've overridden the port
		// then this becomes a dup because of us, not DNS; we still skip the dup.
		//
		// We ignore weight & priority because we check them all, in parallel.
		var hn string
		if port != "" {
			hn = net.JoinHostPort(srv.Target, port)
		} else {
			// uint16 should always fit inside int
			hn = net.JoinHostPort(srv.Target, strconv.Itoa(int(srv.Port)))
		}
		if _, already := seen[hn]; already {
			status.Messagef("skipping dup SRV hostport: %q", hn)
			continue
		}
		seen[hn] = struct{}{}
		probeHostGo(hn, status, domain)
	}
}
