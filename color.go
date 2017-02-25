// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

// ColorRed wraps text in ANSI color sequences for bold red,
// unless -nocolor was given
func ColorRed(msg string) string {
	if opts.noColor {
		return msg
	}
	return "\x1B[1;31m" + msg + "\x1B[0m"
}

// ColorGreen wraps text in ANSI color sequences for bold green,
// unless -nocolor was given
func ColorGreen(msg string) string {
	if opts.noColor {
		return msg
	}
	return "\x1B[1;32m" + msg + "\x1B[0m"
}
