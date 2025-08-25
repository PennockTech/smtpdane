#!/bin/sh -eu
set -eu

repo_root="$(git rev-parse --show-toplevel)"

set -x

go get -u
go mod tidy
go list -mod=mod -m -retracted all > /dev/null

cd "$repo_root/.github/workflows"
pinact run -u -- *.y*ml

cd "$repo_root"
zizmor --persona pedantic .
