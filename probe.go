// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"net"
)

// probeHost is the top-level function of a go-routine and is responsible for
// probing one remote SMTP connection.
//
// Messages should be reported via the Output function of the status; newlines
// are appended and each string is guaranteed to be emitted with no
// interweaving of other results within the string.
func probeHost(hostSpec string, status *programStatus) {
	defer status.probing.Done()

	hostname, port, err := HostnamePortFrom(hostSpec)
	if err != nil {
		status.Errorf("error parsing %q: %s", hostSpec, err)
		return
	}

	ipList, err := resolveSecure(hostname)
	if err != nil {
		status.Errorf("error resolving %q: %s", hostname, err)
		return
	}

	status.Messagef("found %d addresses for %q: %v", len(ipList), hostname, ipList)

	for _, ip := range ipList {
		status.probing.Add(1)
		go probeAddr(ip, hostname, port, status)
	}
}

func probeAddr(ip net.IP, hostname string, port int, status *programStatus) {
	defer status.probing.Done()

	status.Errorf("unimplemented probeAddr(%v, %s, %d)", ip, hostname, port)
}
