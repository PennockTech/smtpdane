// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"fmt"
	"runtime"
	"strings"
)

const programName = "smtpdane"

// may be updated by the linker on the link command-line when compiling
var VersionString string = "0.2.2"

// may be updated by the linker on the link command-line when compiling
var RepoVersionString string = ""

func version() {
	fmt.Printf("%s: Version %s\n", programName, VersionString)
	fmt.Printf("%s: Golang: Runtime: %s\n", programName, runtime.Version())

	if RepoVersionString != "" {
		// Linker cmdline hack: use Unit Separator US (0x1F) within Record Separator terminated records (RS, 0x1E)
		// And whitespace replaced with Substitute (0x1A)
		for _, l := range strings.Split(RepoVersionString, "\x1E") {
			if l != "" {
				l = strings.Replace(l, "\x1A", " ", -1)
				units := strings.SplitN(l, "\x1F", 2)
				if len(units) == 1 {
					units = append(units, "<unknown>")
				}
				fmt.Printf("%s: repo %q: %q\n", programName, units[0], units[1])
			}
		}
	} else {
		fmt.Printf("%s: no repo version details available\n", programName)
	}
}
