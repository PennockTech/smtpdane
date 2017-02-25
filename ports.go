// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

// I like the Perl idiom for ports of `name(number)`, to look up the name in
// services and if not found, then fall back to using the given number.

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
)

const minPort = 1
const maxPort = 65535

var portRE *regexp.Regexp

func init() {
	portRE = regexp.MustCompile(`^([A-Za-z0-9._-]+)(?:\((\d+)\))?$`)
}

// Parse a port specification and return a valid port number, or an error.
// Ports are bound to [1,65535].  Specification can be a numeric port, or a
// service name, or "service(number)" to use the name if known, falling back
// to the supplied port.  Numbers can be in any base recognized by Golang as
// a spec spec.
func PortParse(spec string) (int, error) {
	u64, err := strconv.ParseUint(spec, 0, 16)
	if err == nil {
		if u64 < minPort || maxPort < u64 {
			return 0, fmt.Errorf("invalid port number, out of range: %d", u64)
		}
		return int(u64), nil
	}

	matches := portRE.FindStringSubmatch(spec)
	if matches == nil {
		return 0, fmt.Errorf("unable to parse: %q", spec)
	}
	if len(matches) < 2 {
		panic("bad matches array")
	}

	port, nameErr := net.LookupPort("tcp", matches[1])
	if nameErr == nil {
		return port, nil
	}

	if len(matches) < 3 {
		return 0, nameErr
	}

	u64, err = strconv.ParseUint(matches[2], 0, 16)
	if err == nil {
		if u64 < minPort || maxPort < u64 {
			return 0, fmt.Errorf("%s and %d also out of range", nameErr, u64)
		}
		return int(u64), nil
	}

	return 0, fmt.Errorf("%s and %s", nameErr, err)
}

func HostnamePortFrom(spec string) (string, int, error) {
	h, p, err := net.SplitHostPort(spec)
	if err == nil {
		p2, err := PortParse(p)
		return h, p2, err
	}

	if _, ok := err.(*net.AddrError); ok {
		// either too many colons or missing port; assume missing port, let
		// error out later, since there's no way to tell without string
		// matching.
		return spec, opts.defaultPortInt, nil
	}

	return "", 0, err
}

func HostnameMaybePortFrom(spec string) (string, string, error) {
	h, p, err := net.SplitHostPort(spec)
	if err == nil {
		p2, err := PortParse(p)
		return h, strconv.Itoa(p2), err
	}

	if _, ok := err.(*net.AddrError); ok {
		// either too many colons or missing port; assume missing port, let
		// error out later, since there's no way to tell without string
		// matching.
		return spec, "", nil
	}

	return "", "", err
}

func HostPortWithDefaultPort(spec string, defaultPort string) string {
	_, _, err := net.SplitHostPort(spec)
	if err == nil {
		return spec
	}

	// Similarly, there might be other errors than missing port here; figure
	// out if we want to handle those, or let error occur later.

	return net.JoinHostPort(spec, defaultPort)
}
