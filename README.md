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

To avoid requiring a local DNSSEC validating DNS resolver, DNSSEC is validated
inside the `smtpdane` tool.  To achieve this, the root zone trust anchors are
baked into the code.  Every few years these are rotated and `smtpdane` will
need to be updated and rebuilt. _\[NB: this functionality not yet implemented,
still rely upon a validating resolver right now.\]_

Optionally this client can speak TLS-on-connect instead of STARTTLS, to aid
with monitoring `smtps` (commonly deployed on the non-IANA-assigned port 465).

The tool will connect to each SMTP server specified, in parallel.  If there
are multiple IP addresses, then each will be connected to, in parallel.


### Access needed

1. Network connectivity, outbound on port 53, UDP and TCP
2. Outbound TCP, on port 25 and any other ports required for monitoring SMTP.
   (587 and 465 are common choices).
3. Stdio, ability to write to stdout.
4. `/etc/resolv.conf` unless the `DNS_RESOLVER` environment variable is set.
5. No other filesystem access should be required, if statically linked.


## Installation

Go 1.8 or greater is required.  We use the
`crypto/tls.Config.VerifyPeerCertificate` callback introduced in that release.

```console
$ mkdir ~/go
$ export GOPATH="$HOME/go"		# unnecessary from Go 1.8 onwards
$ go get go.pennock.tech/smtpdane
```

With those install steps, the binary can be found in `~/go/bin/smtpdane`.
The `go get` command will fetch this repo, any dependent repos and perform the
build.

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
Use `-tls-on-connect` to immediately start TLS instead of negotiating.

The port can be included with the host in the usual `:1234` suffix notation;
if the host is an IPv6 address, either do not include a port or use the
otherwise-optional square-brackets, thus `[2001:db8::25]:1234`.


[RFC7672]: https://tools.ietf.org/html/rfc7672
           "SMTP Security via Opportunistic DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS)"

