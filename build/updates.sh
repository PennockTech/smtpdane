#!/bin/sh -eu
set -eu

repo_root="$(git rev-parse --show-toplevel)"
progname="${0##*/}"
stderr() { printf >&2 '%s: %s\n' "$progname" "$*"; }

# This roughly matches the output format of `set -x` but lets us interleave
# more complex functions and be more explicit about what we actually run.
run() {
  printf >&2 '+ %s\n' "$*"
  "$@"
}

set_retracted_golang() {
  local t
  t="$(go list -mod=mod -m -retracted -f '{{if .Retracted}}  {{.Path}} is retracted{{end}}' all)"
  if [ -n "$t" ]; then
    RETRACTED="$t"
    return 1
  fi
  return 0
}


# This one reports the _PRIOR_ state, which we might be moving away from, and
# is to let us know if we were using code which had to be retracted, so we can
# investigate the cause.  Fingers crossed that it's not a supply chain attack.
stderr "checking if prior state includes retracted dependencies"
set_retracted_golang || true

stderr "updating Go dependencies"
run go get -u
run go mod tidy
# This one syncs any additional go.sum changes needed:
run go list -mod=mod -m -retracted all > /dev/null
# and this one will report any retracted dependencies as an error:
if ! set_retracted_golang; then
  stderr "error: retracted dependencies exist:"
  printf >&2 '%s\n' "$RETRACTED"
  exit 1
fi

stderr "updating GitHub Actions"
run cd "$repo_root/.github/workflows"
run pinact run -u -- *.y*ml
run cd "$repo_root"

stderr "auditing GitHub Actions"
run zizmor --persona pedantic .
