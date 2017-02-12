// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

// probeHost is the top-level function of a go-routine and is responsible for
// probing one remote SMTP connection.
//
// Messages should be reported via the Output function of the status; newlines
// are appended and each string is guaranteed to be emitted with no
// interweaving of other results within the string.
func probeHost(hostSpec string, status *programStatus) {
	defer func() {
		status.probing.Done()
	}()

	status.Messagef("not implemented for %s", hostSpec)
	status.AddErr()
}
