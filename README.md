smtpdane
========

**EARLY ALPHA SOFTWARE**

**THIS HAS NOT YET BEEN TESTED TO CONFIRM IT FAILS WHEN IT SHOULD, AGAINST BAD
CERTIFICATES OR DNS**

Go 1.8+ : `go get go.pennock.tech/smtpdane`

This is an SMTP client which can connect to an SMTP server, issue `STARTTLS`
and verify the certificate using DANE (TLSA records signed with DNSSEC).
Validity of the certificate is checked, including date validity periods, but
not PKIX CA anchoring.

Per [RFC7672][] we only support `DANE-TA(2)` and `DANE-EE(3)`;
`PKIX-TA(0)` and `PKIX-EE(1)` are explicitly unsupported.

~~To avoid requiring a local DNSSEC validating DNS resolver, DNSSEC is validated
inside the `smtpdane` tool.  To achieve this, the root zone trust anchors are
baked into the code.  Every few years these are rotated and `smtpdane` will
need to be updated and rebuilt.~~ _\[NB: this functionality not yet implemented,
still rely upon a validating resolver right now.\]_

Optionally this client can speak TLS-on-connect instead of STARTTLS, to aid
with monitoring `smtps` (commonly deployed on the non-IANA-assigned port 465).

The tool will connect to each SMTP server specified, in parallel.  If there
are multiple IP addresses, then each will be connected to, in parallel.

Flags may be used to request looking up MX records or SRV records for a
domain.


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


## Installation

Go 1.8 or greater is required.  We use the
`crypto/tls.Config.VerifyPeerCertificate` callback introduced in that release.

```console
$ mkdir ~/go
$ go get go.pennock.tech/smtpdane
```

With those install steps, the binary can be found in `~/go/bin/smtpdane`.
The `go get` command will fetch this repo, any dependent repos and perform the
build.  This assumes that `$GOPATH` and other Golang-controlling environment
variables have not been set; as of Go 1.8, `~/go` is the default solitary
entry in the `$GOPATH` list.

To build as a static binary for deployment into a lib-less environment:

```sh
go build -ldflags "-linkmode external -extldflags -static"
```

At this time there is no vendoring of dependencies.  If this matters in your
environment, capture them for your use-cases.  If our dependency list grows to
include packages with unstable APIs then this decision will be revisited.


## Invoking

Invoke with `-help` to see help output listing known flags and defaults.

The host to connect to is provided as a list of one or more hosts after any
options.

Use `-port` to specify a different port to speak on, for each host which
doesn't specify a specific port.
Note that `-port` specifies a default; if looking up SRV records, ports from
SRV override the `-port` option.  However, port overrides on the host override
SRV.

Use `-tls-on-connect` to immediately start TLS instead of negotiating.

The port can be included with the host in the usual `:1234` suffix notation;
if the host is an IPv6 address, either do not include a port or use the
otherwise-optional square-brackets, thus `[2001:db8::25]:1234`.

By default, the `EHLO` command will supply a hostname of `smtpdane.invalid`;
use the `-helo` flag to override that value.

### Examples

```sh
# Regular lookup of a host; check every address-record:
smtpdane mx1.example.org

# Regular lookup of a domain; check every MX, every address:
smtpdane -mx example.org

# Regular lookup of SMTP Submission for a domain:
smtpdane -submission example.org

# Connect to port 26 for a server:
smtpdane -port 26 mx1.example.org

# Check TLS-on-connect for a server:
smtpdane -port 465 -tls-on-connect smtp.example.org

# Connect to the "usual" de-facto standard TLS-on-connect SMTPS port,
# on each host which is a submission host for the domain,
# and speak TLS-on-connect:
smtpdane -tls-on-connect -submission example.org:465

# Also try checking another hostname
smtpdane -aka mail.example.net mail.example.org
```

Note that the `-aka` names are added to the list of "acceptable" names; you'll
see each success/failure if you pay attention to the output, but as long as
_one_ name succeeds, the probe of that `host:ip` will be deemed a success.


[RFC7672]: https://tools.ietf.org/html/rfc7672
           "SMTP Security via Opportunistic DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS)"

