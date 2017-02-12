// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"net"
)

func resolveSecure(hostname string) ([]net.IP, error) {
	l := make([]net.IP, 2)
	l[0] = net.ParseIP("192.0.2.3")
	l[1] = net.ParseIP("2001:db8::4")
	return l, nil
}
