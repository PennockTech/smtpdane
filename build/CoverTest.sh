#!/bin/sh
#
# Relies upon: <https://github.com/wadey/gocovmerge>
#
# Based upon mmindenhall's solution in <https://github.com/golang/go/issues/6909>
#

TOP="go.pennock.tech/$(basename $(git rev-parse --show-toplevel))"

progname="$(basename "$0")"
trace() { printf >&2 "%s: %s\n" "$progname" "$*" ; }

trace "removing old c*.out files"
find . -name c\*.out -execdir rm -v {} \;

trace "generating new c.partial.out files"
for D in $(find . -name .git -prune -o -type d -print)
do
	if [ $D = "." ]; then
		go test -covermode=count -coverprofile=c.partial.out -coverpkg ./... .
		continue
	fi
	( cd $D && \
		go test -covermode=count -coverprofile=c.partial.out -coverpkg "$TOP,./..." .
	)
done

trace "combining coverage files -> coverage.out"
gocovmerge $(find . -name .git -prune -o -name c.partial.out -print) > coverage.out

trace "suggestions:"
echo "  go tool cover -func=coverage.out | less"
echo "  go tool cover -html=coverage.out"
