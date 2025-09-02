#!/bin/sh -eu
set -eu

repo_root="$(git rev-parse --show-toplevel)"

set -x

go get -u
go mod tidy
# This one syncs any additional go.sum changes needed:
go list -mod=mod -m -retracted all > /dev/null
# and this one will report any retracted dependencies as an error:
set +x
t="$(go list -m -retracted -f '{{if .Retracted}}  {{.Path}} is retracted{{end}}' all)"
if [ -n "$t" ]; then
  printf >&2 '%s: error: retracted dependencies exist:\n' "${0##*/}"
  printf >&2 '%s\n' "$t"
  exit 1
fi

set -x
cd "$repo_root/.github/workflows"
pinact run -u -- *.y*ml

cd "$repo_root"
zizmor --persona pedantic .
