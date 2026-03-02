#!/usr/bin/env bash
set -euo pipefail

readonly COMMIT_MESSAGE_FIRSTLINE_PREFIX='smtpdane version'

# If the script needs more than this, then switch to using _lib.sh
readonly progname="${0##*/}"
declare -i VERBOSE=0
stderr() { printf >&2 '%s: %s\n' "$progname" "$*"; }
die_n() { local ev="$1"; shift; stderr "$@"; exit "$ev"; }
readonly EX_USAGE=64 EX_DATAERR=65 EX_UNAVAILABLE=69 EX_SOFTWARE=70

REQUIRED_COMMANDS=( semver-cli gofmt sed git go )
declare -i okay=1
for cmd in "${REQUIRED_COMMANDS[@]}"; do
	if command -v "$cmd" >/dev/null 2>&1; then continue; fi
	stderr "missing tool: ${cmd@Q}"
	okay=0
done
(( okay )) || exit $EX_UNAVAILABLE

stderr 'checking if repo is clean'
output="$(git status --porcelain 2>&1 )" || die_n $? "git -C status died $?"
if [[ -n "$output" ]]; then
	printf >&2 '%s\n' "$output"
	die_n $EX_DATAERR "git status indicates repo is not clean, refusing to proceed"
fi

stderr 'fetching remotes, checking if branch is up-to-date'
git remote update
output="$(git rev-list --left-only --boundary '@{upstream}...' 2>&1)" || die_n $? "git rev-list died $?"
if [[ -n "$output" ]]; then
	printf >&2 '%s\n' "$output"
	die_n $EX_DATAERR "local branch behind upstream version, update first please"
fi
stderr "up-to-date"

latest=$(git tag --list 'v*' --sort=-version:refname | head -n1)
bump_minor="v$(semver-cli inc minor "$latest")"
bump_patch="v$(semver-cli inc patch "$latest")"
stderr "latest tag: ${latest@Q} ; if bump patch: ${bump_patch@Q}  if bump minor: ${bump_minor@Q}"
oPS3="${PS3:-}"
PS3='Select how to bump version> '
select choice in "patch-level $bump_patch" "minor-level $bump_minor" abort; do
	case "$choice" in
		patch*) want="$bump_patch"; break ;;
		minor*) want="$bump_minor"; break ;;
		abort) exit 1 ;;
	esac
done
[[ -n "${want:-}" ]] || exit 1  # EOF
PS3="$oPS3"

release_embedded_version="${want#v}"
post_release_embedded_version="$(semver-cli inc patch "$want")-dev"
stderr "want: ${want@Q} (Version=${release_embedded_version@Q}  and then after release Version=${post_release_embedded_version@Q})"

stderr "rewriting version.go and then compiling"
sed -E -i '' "s/Version[[:space:]]*string[[:space:]]*=[[:space:]]*\"[^\"]*\"/Version string = \"$release_embedded_version\"/" version.go
gofmt -w version.go
go build -v .

stderr "committing and placing tag (you get to edit)"
git commit -m "RELEASE: bump version to ${want}" -o version.go
git tag -m "${COMMIT_MESSAGE_FIRSTLINE_PREFIX} ${want}" -e "${want}"

stderr "rewriting version.go post-release"
sed -E -i '' "s/Version[[:space:]]*string[[:space:]]*=[[:space:]]*\"[^\"]*\"/Version string = \"$post_release_embedded_version\"/" version.go
gofmt -w version.go
git commit -m "RELEASE: post-tag bump version to v${post_release_embedded_version}" -o version.go
