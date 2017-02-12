// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"fmt"
	"runtime"
)

const programName = "smtpdane"

// may be updated by the linker on the link command-line when compiling
var VersionString string = "0.1"

func version() {
	fmt.Printf("%s: Version %s\n", programName, VersionString)
	fmt.Printf("%s: Golang: Runtime: %s\n", programName, runtime.Version())
}
