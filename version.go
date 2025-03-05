// Copyright © 2017,2020 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

const ProjectName = "smtpdane"

// may be updated by the linker on the link command-line when compiling
var (
	Version     string = "0.5.4"
	Commit             = ""
	CompileDate        = ""
	BuiltBy            = ""
)

func version() {
	fmt.Printf("%s version %s\n", ProjectName, Version)
	if Commit != "" {
		fmt.Printf("%s commit %s\n", ProjectName, Commit)
	}
	if CompileDate != "" {
		fmt.Printf("%s compile-date: %s\n", ProjectName, CompileDate)
	}
	if BuiltBy != "" {
		fmt.Printf("%s built-by: %s\n", ProjectName, BuiltBy)
	}

	fmt.Printf("%s: Golang: Runtime: %s\n", ProjectName, runtime.Version())

	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		fmt.Printf("%s: no repo version details available\n", ProjectName)
		return
	}

	type versionLine struct {
		path, version, sum string
		replaced           bool
	}
	lines := make([]versionLine, 0, 10)
	addVersion := func(p, v, sum string, replaced bool) {
		lines = append(lines, versionLine{p, v, sum, replaced})
	}

	m := &buildInfo.Main
	topVersion := m.Version
	if Version != "" {
		topVersion = Version
	}
	addVersion(m.Path, topVersion, m.Sum, m.Replace != nil)
	for m.Replace != nil {
		m = m.Replace
		addVersion(m.Path, m.Version, m.Sum, m.Replace != nil)
	}

	for _, m := range buildInfo.Deps {
		addVersion(m.Path, m.Version, m.Sum, m.Replace != nil)
		for m.Replace != nil {
			m = m.Replace
			addVersion(m.Path, m.Version, m.Sum, m.Replace != nil)
		}
	}

	headers := []string{"Path", "Version", "Checksum", "Replaced"}
	maxP, maxV, maxS := len(headers[0]), len(headers[1]), len(headers[2])
	for _, l := range lines {
		if len(l.path) > maxP {
			maxP = len(l.path)
		}
		if len(l.version) > maxV {
			maxV = len(l.version)
		}
		if len(l.sum) > maxS {
			maxS = len(l.sum)
		}
	}
	fmt.Printf("%-*s %-*s %-*s %s\n", maxP, headers[0], maxV, headers[1], maxS, headers[2], headers[3])
	for _, l := range lines {
		fmt.Printf("%-*s %-*s %-*s %v\n", maxP, l.path, maxV, l.version, maxS, l.sum, l.replaced)
	}
}
