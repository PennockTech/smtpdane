smtpdane
========

[![Continuous Integration](https://secure.travis-ci.org/PennockTech/smtpdane.svg?branch=main)](http://travis-ci.org/PennockTech/smtpdane)
[![Coverage Status](https://coveralls.io/repos/github/PennockTech/smtpdane/badge.svg)](https://coveralls.io/github/PennockTech/smtpdane)

SMTP Service monitoring of DANE-protected services, with optional
NAGIOS-compatible behavior.

A bit short on tests but has been used for a few years now and so far has both
succeeded when it should and failed when it should.

---

Go 1.14+ : `go get go.pennock.tech/smtpdane`  _(optional helpers documented below)_

This is an SMTP client which can connect to an SMTP server, issue `STARTTLS`
and verify the certificate using DANE (TLSA records signed with DNSSEC).
Validity of the certificate is checked, including date validity periods, but
not PKIX CA anchoring.

Per [RFC7672][] we only support `DANE-TA(2)` and `DANE-EE(3)`;
`PKIX-TA(0)` and `PKIX-EE(1)` are explicitly unsupported.

This relies upon a validating DNS resolver; we do not yet validate internally.
(Most tools should not validate themselves, but perhaps a monitoring tool
should?)

Optionally this client can speak TLS-on-connect instead of STARTTLS,
for [RFC8314][] `submissions` service (historically called `smtps` or
`ssmtp`); this is port 465 mail service for clients to submit mail.

The tool will connect to each SMTP server specified, in parallel.  If there
are multiple IP addresses, then each will be connected to, in parallel.

Flags may be used to request looking up MX records or SRV records for a
domain.


## Installation

Go 1.14 or greater is required; the release of Go 1.15 changed how network
errors are returned in some situations; while we didn't happen to hit those,
it's now just a matter of time before our situation breaks too, so switched to
the `errors.As()` replacement for interface casting, as introduced in Go 1.13.
We use `tls.CipherSuiteName()` from Go 1.14 for better diagnostics.

```console
$ go get go.pennock.tech/smtpdane
```

( ~~Go 1.8 or greater is required.  We use the
`crypto/tls.Config.VerifyPeerCertificate` callback introduced in that
release.~~ )

Optionally, use `./.compile` instead of `go build` to embed extra repository
information into the binary, but this is less necessary with Go Modules.

With that one `go get` command, assuming no other Go environment variables set
up to move things from defaults, the binary can be found in
`~/go/bin/smtpdane`.  If `$GOPATH` is set, then look in `bin/` inside the
first directory in the list given by that variable.

To just download, use `go get -d`.

To build as a static binary for deployment into a lib-less environment:

```sh
go get -d go.pennock.tech/smtpdane
# simple
~/go/src/go.pennock.tech/smtpdane/.compile static
# manual:
cd /go/src/go.pennock.tech/smtpdane
go build -ldflags "-linkmode external -extldflags -static"
```

At this time there is no vendoring of dependencies.  If this matters in your
environment, capture them for your use-cases.  If our dependency list grows to
include packages with unstable APIs then this decision will be revisited.

Our version numbering is semantic, with the caveat that Go only supports
the latest two minor versions of the toolsuite, and PennockTech does not
consider it a breaking change to add a dependency upon a stdlib feature which
is present in all releases of Go which are currently supported by the Go
language maintainers.


## Invoking

Invoke with `-help` to see help output listing known flags and defaults.  
See the examples below which make it clear how simple it normally is.

Most commonly: `smtpdane -mx my-domain.example.org`

The host to connect to is provided as a list of one or more hosts after any
options.

Use `-port` to specify a different port to speak on, for each host which
doesn't specify a specific port.
Note that `-port` specifies a default; if looking up SRV records, ports from
SRV override the `-port` option.  However, port overrides on the host (see
below) override SRV.

Use `-tls-on-connect` to immediately start TLS instead of negotiating.  
Use `-mx` to indicate that names supplied are domain-names and MX records
should be looked up.  
Use `-submission` to do the same but look up service `submission` SRV records,
typically used for port 587 service.  
Use `-submissions` to do the same, looking up for `submissions` though and
forcing on the `-tls-on-connect` option.

The port can be included with the host in the usual `:1234` suffix notation;
if the host is an IPv6 address, either do not include a port or use the
otherwise-optional square-brackets, thus `[2001:db8::25]:1234`.

By default, the `EHLO` command will supply a hostname of `smtpdane.invalid`;
use the `-helo` flag to override that value.

Use `-quiet` (or `-q`) to not emit any messages unless there's a failure.  
Use `-terse` to shorten the amount of output text.  
Use `-nagios` to use Nagios exit codes (and be `-terse` & `-nocolor`).

The `-quiet` approach is suitable for cron jobs which should only emit when
there's a problem.  The `-nagios` approach is better for less ad-hoc
monitoring.  We're open to supporting other output formats for other
monitoring systems.

### Examples

```sh
# Regular lookup of a host; check every address-record:
smtpdane mx1.example.org

# Regular lookup of a domain; check every MX, every address:
smtpdane -mx example.org

# Be invoked for Nagios monitoring, with terse output, no color codes,
# avoiding stderr, but checking for OCSP (& DANE) on all MX servers
smtpdane -nagios -expect-ocsp -mx example.org

# Regular lookup of SMTP Submission for a domain:
smtpdane -submission example.org

# Regular lookup of SMTP Submissions TLS-on-connect for a domain:
smtpdane -submissions example.org

# Connect to port 26 for a server, IPv4-only:
smtpdane -4 -port 26 mx1.example.org

# Check if there is a Submissions (TLS-on-connect, 465) service on
# each IP found for Submission service (587) to confirm that you're
# good to add the newer _submissions._tcp SRV records too:
smtpdane -tls-on-connect -submission example.org:465

# When verifying the certificate, add a different allowed hostname
smtpdane -aka mail.example.net mail.example.org

# See much more information about the certs
smtpdane -show-cert-info -mx example.org

# See expiring certificates much sooner; alas, Golang duration parsing
# maxes out in units of hours, so extend in shell;
# 3 months of 31 days each, 24 hours per day, don't forget 'h' unit
smtpdane -expiration-warning $((3*31*24))h -mx example.org

# Turn missing OCSP stapling information into an error
smtpdane -expect-ocsp -mx example.org
```

Note that the `-aka` names are added to the list of "acceptable" names; you'll
see each success/failure if you pay attention to the output, but as long as
_one_ name succeeds, the probe of that `host:ip` will be deemed a success.

The expiration time of _all_ certificates in the validated chain is checked
for validity, unless `-expiration-warning 0s` is passed.
This examines the `NotAfter` time.  `NotBefore` is ignored.
Only the validated chains are examined, so multiple-chain presentations
require more care to check each thoroughly (suggestions welcome).
While a normal TLS client only checks the current time, smtpdane checks two
times: it checks for outright expired certificates, treating those as errors,
and it checks for "expiring soon" certificates, treating those as warnings.
To effectively only check for outright expiry, use `-expiration-warning 1ns`
to shift the warning to be enabled with a 1 nanosecond warning period; this
leaves warnings as technically possible, albeit somewhat unlikely.

OCSP status is only reported if either `-show-cert-info` or
`-expect-ocsp` is passed.  The latter will cause missing OCSP information to
be treated as an error, and present/good OCSP information to be shown in
green.  Note that a `TryLater` response-code is treated as a warning.

A simple invocation for a `crontab(5)` might be:

```
17 */3 * * * /home/myname/go/bin/smtpdane -q -expect-ocsp -mx example.org
```

That will check every 3 hours, at 17 minutes past the hour, and check every IP
for every hostname returned by the MX records for the domain, checking
certificate validity with default notification periods, and declaring an
absence of OCSP information to be an error.  No output will be produced as
long as everything is fine, but there will be output if there are problems,
and cron will send an email.


### Access needed

You should be able to write a security sandbox profile to constrain this tool,
based upon the information here.  If it's not listed but is needed, then
that's a documentation bug, please report it.

1. Network connectivity, outbound on port 53, UDP and TCP
   + If `/etc/resolv.conf` or `DNS_RESOLVER` specifies another port, then that
     port too
   + If invoked with a hostname which dispatches to multicast DNS, then likely
     port 5353
2. Outbound TCP, on port 25 and any other ports required for monitoring SMTP.
   (587 and 465 are common choices).
   + Ports can be supplied on the command-line, or via SRV records if invoked
     with `-srv`
3. Stdio, ability to write to stdout/stderr.
4. `/etc/resolv.conf`
   + If the `DNS_RESOLVER` environment variable is set, it's used for
     resolution, but the libraries still load this file
5. Read-only access to `$SSL_CERT_FILE` and `$SSL_CERT_DIR` locations, and if
   neither of those is set then to a set of common locations for those files.
   + Inhibit with `-nocertnames`
6. Read-only access to `/etc/services`; on many OSes also `/etc/nsswitch.conf`
   to handle indirection to that, and then if that's _not_ just the file, then
   wherever else services are read from.  Sometimes other `/etc` files used
   for DNS resolution.
7. Usually some source of system entropy (`/dev/urandom`) if not available via
   a system call.
8. Any other common OS start-up files used even for statically linked files.
   + Eg, `/etc/malloc.conf` on some OSes
9. No other filesystem access should be required, if statically linked.
   + otherwise, everything used by the dynamic loader too


[RFC7672]: https://tools.ietf.org/html/rfc7672
           "SMTP Security via Opportunistic DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS)"
[RFC8314]: https://tools.ietf.org/html/rfc8314
           "Cleartext Considered Obsolete: Use of Transport Layer Security (TLS) for Email Submission and Access"
