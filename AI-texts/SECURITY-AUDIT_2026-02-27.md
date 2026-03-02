# Security Audit: smtpdane

**Audit Date:** 2026-02-26
**Auditor:** Claude (claude-sonnet-4-6), automated multi-agent review
**Scope:** Full codebase review — network/protocol, cryptography/PKI, resource/DoS, input/parsing, concurrency

---

## Executive Summary

`smtpdane` connects to SMTP servers that may be adversarial. Five specialist sub-agents reviewed the
codebase, cross-checking findings from network/protocol, crypto/PKI, resource/DoS, input/parsing,
and concurrency perspectives.

**Critical findings (2):** Both can be triggered by any server `smtpdane` connects to, requiring no
prior authentication or trust. The most impactful is the absence of per-operation timeouts after TCP
connection — a hostile server can hang any probe goroutine indefinitely. The second critical finding
is a data race on a shared DNS client field.

**High findings (1):** The `certDetails` channel can deadlock if a server presents enough matching
certificate chains to fill the 64-slot buffer before the drain goroutine runs.

**Medium findings (2):** CNAME records in DNS answer sections are silently dropped (could cause false
negatives); DNSSEC validation is delegated to the resolver's AD bit (documented limitation).

**Low findings (1):** Path construction in `known_certs.go` uses string concatenation instead of
`filepath.Join` (no security impact in practice, but not idiomatic).

---

## Findings

### [SMTP-1] CRITICAL — No per-operation timeouts after TCP connect

**Location:** `probe.go` ~line 287 (`probeAddr`), ~line 329 (`probeConnectedAddr`),
~line 382 (`tryTLSOnConn`). TODO comment at line 349 acknowledges the gap.

**Description:**
`net.DialTimeout()` establishes only a TCP-connect timeout. Once the TCP connection is accepted,
the raw `net.Conn` is passed to `smtp.NewClient()`, `tls.Client()`, and `textproto.NewConn()`
with **no deadline set**. Every subsequent operation — reading the SMTP 220 banner, sending EHLO,
negotiating STARTTLS, performing the TLS handshake, sending QUIT — can block indefinitely if the
server stalls.

Affected call sites:

| Code path | Blocking operation | File:approx-line |
|---|---|---|
| STARTTLS path | `smtp.NewClient()` (reads banner) | `probe.go:342` |
| STARTTLS path | `s.Hello()` (sends/reads EHLO) | `probe.go:354` |
| STARTTLS path | `s.StartTLS()` (TLS handshake) | `probe.go:369` |
| STARTTLS path | `s.Quit()` | `probe.go:376` |
| TLS-on-connect | `tls.Client()` (TLS handshake implicit) | `probe.go:384` |
| TLS-on-connect | `t.ReadResponse(220)` (banner) | `probe.go:387` |
| TLS-on-connect | `t.ReadResponse(250)` (EHLO) | `probe.go:399` |
| TLS-on-connect | `t.ReadResponse(221)` (QUIT) | `probe.go:411` |
| TLS-on-connect | `t.ReadLine()` (TLS teardown) | `probe.go:421` |

**Attack scenario:**
A malicious SMTP server accepts TCP, sends the opening SYN-ACK, then sends nothing. The probe
goroutine enters `smtp.NewClient()` and blocks forever waiting for the 220 banner. With many
targets each using a stalling server, all probe goroutines accumulate with no cleanup path.

**Fix:** Set `conn.SetDeadline(time.Now().Add(opts.operationTimeout))` immediately after dial, in
`probeConnectedAddr()`, covering all subsequent operations on that connection. A single deadline
call is sufficient because Go's `net/smtp`, `crypto/tls`, and `net/textproto` all use the same
underlying `net.Conn`.

See [Recommended Fixes — SMTP-1](#fix-smtp-1).

---

### [DNS-1] CRITICAL — Data race on `dns.Client.Net` field

**Location:** `resolve.go:145,197`, `resolveRRmaybeSecure()`

**Description:**
`dnsSettings.client` is a package-level singleton `*dns.Client`. In `resolveRRmaybeSecure()`, the
loop body does:

```go
c.Net = "udp"              // line 145 — write
...
r, _, err = c.Exchange(m, resolver)   // line 152 — concurrent use
...
if r.Truncated {
    c.Net = "tcp"          // line 197 — write, only RLock held (or none)
    goto RETRY_DNS_LOOKUP
}
```

Multiple goroutines call this function concurrently (one per hostname, one per IP). Each goroutine
writes `c.Net = "udp"` at the top of the loop and may write `c.Net = "tcp"` on truncation — all
on the same `*dns.Client` pointer — while `initDNS()` holds only a read lock during the fast path.
The `Exchange()` call itself also reads `c.Net` internally. This is a textbook data race.

**Detectability:** `go test -race` will flag this.

**Attack scenario:**
A DNS server that returns truncated UDP responses (forcing TCP retry) while another goroutine is
mid-query can corrupt both goroutines' transport selection, causing incorrect query behaviour or
a panic in the race detector. Not directly exploitable to inject data, but can cause incorrect
"no TLSA" assessments and undefined behaviour.

**Fix:** Create a per-call `*dns.Client` instead of mutating the shared singleton. The struct is
small; allocation cost is negligible against network I/O.

See [Recommended Fixes — DNS-1](#fix-dns-1).

---

### [DANE-1] HIGH — `certDetails` channel can deadlock with ≥65 matching TLSA chains

**Location:** `dane.go:36`, `peerCertificateVerifierFor()`

**Description:**
The FIXME comment in the source already identifies this:

```go
// FIXME: consider absorbing results in a separate go-routine spun up
// before TLS to be proof against even the most abusive servers too.
ch := make(chan certDetails, 64)
```

The `peerCertificateVerifier` callback runs inside Go's TLS stack during the handshake. It sends
`certDetails` items to `ch`. The goroutine that drains `ch` (`checkCertInfo()`) is called *after*
`s.StartTLS()` or `tls.Client()` returns — i.e., after the handshake. If the verifier sends ≥65
items before the handshake returns, the 65th send blocks, which blocks the TLS handshake, which
never returns, which means `checkCertInfo()` never runs — permanent deadlock.

**Trigger condition:** Many TLSA records × many CA certs in chain × DANE-TA(2) matching. Each
`(tlsa, caCert)` pair that passes `Verify()` *and* `chainValid()` writes one item. In practice
this is rare, but a crafted server with many TLSA records in DNS could trigger it.

**Fix:** Buffer into an unbounded intermediate collector goroutine started before the TLS handshake.
The collector reads from an internal channel (bounded) and re-emits to the external channel after
the verifier closes the internal channel.

See [Recommended Fixes — DANE-1](#fix-dane-1).

---

### [DNS-2] MEDIUM — CNAME records in DNS answer section silently ignored

**Location:** `resolve.go:224`, comment `// TODO: CNAME?`

**Description:**
When iterating `r.Answer`, records whose `Rrtype` doesn't match the requested type are skipped:

```go
for _, rr := range r.Answer {
    // TODO: CNAME?
    if rr.Header().Rrtype != typ {
        continue   // CNAME records are silently dropped
    }
    ...
}
```

If a resolver returns a CNAME in the answer section (common for AAAA or A queries), the resolution
loop finds no matching records and falls through to the "no results found" error. This could cause
`smtpdane` to report a TLSA lookup failure when one would have succeeded via CNAME following.

**Impact:** False-negative security assessments (tool reports "no TLSA" when TLSA exists behind a
CNAME). Not directly exploitable for active attack but could cause DANE to appear broken.

**Fix:** Log a debug message when a CNAME is encountered instead of silently skipping. Full CNAME
following is a larger change deferred to future work.

See [Recommended Fixes — DNS-2](#fix-dns-2).

---

### [DNS-3] LOW — DNSSEC validation delegated to resolver AD bit

**Location:** `resolve.go:93–96`, FIXME comment

**Description:**
```go
// FIXME: This is not doing DNS validation locally.
// It's resolving DNS, delegating trust in validation to the resolver by
// trusting the AD bit.
```

The tool trusts the upstream resolver to set the Authenticated Data (AD) bit correctly. If the
resolver is compromised or the path to it is unencrypted, an attacker on the network can strip the
AD bit or fabricate responses. This is a known architectural limitation, not a new finding.

**Impact:** Requires network-level attacker between `smtpdane` and the configured DNS resolver. Not
locally exploitable in typical deployments with a local validating resolver.

**Mitigation (existing):** Use a local DNSSEC-validating resolver. The `DNS_RESOLVER` environment
variable supports pointing at a trusted resolver.

---

### [LOGIC-1] LOW — `Warnf` calls `Error` instead of `Warn`

**Location:** `messages.go:79-81`

**Description:**
```go
func (s *programStatus) Warnf(spec string, args ...any) {
    s.Error(fmt.Sprintf(spec, args...))  // BUG: should call s.Warn()
}
```

`Warnf` incorrectly delegates to `s.Error()` (which calls `AddErr()`) instead of `s.Warn()` (which calls
`AddWarning()`). Every call to `Warnf` increments the error counter, causing the tool to exit with a
non-zero error code when only warnings occurred.

**Impact:** `Warnf` is called in `probe.go` via `vc.Warnf`. Certificates expiring soon trigger
`vc.Warnf`, which should be a warning but currently causes an error exit.

**Fix:** Change `s.Error(...)` to `s.Warn(...)`.

---

### [CODE-1] LOW — `filepath.Join` vs string concatenation in `known_certs.go`

**Location:** `known_certs.go:212`

**Description:**
```go
data, err := os.ReadFile(directory + "/" + entry.Name())
```

`os.ReadDir` returns entries whose `Name()` method returns only the base filename (never contains
slashes), so no path traversal is possible. However, the idiomatic and portable form is
`filepath.Join(directory, entry.Name())`.

**Impact:** None in practice on Unix. On Windows the separator is `\`; `filepath.Join` handles this
correctly.

**Fix:** Replace with `filepath.Join(directory, entry.Name())`.

---

## Attack Scenarios

### Scenario A: Goroutine exhaustion via stalling SMTP servers (SMTP-1)

An adversary controls one or more SMTP servers whose IP addresses appear in the DNS for target
domains. When `smtpdane` probes those domains:

1. `smtpdane` resolves MX → IP → connects (TCP connect succeeds).
2. Server accepts the connection but never sends the 220 banner.
3. `smtp.NewClient()` in `probeConnectedAddr()` blocks forever with no timeout.
4. The probe goroutine is permanently leaked. `status.probing` WaitGroup never decrements for
   this goroutine.
5. `smtpdane` itself never exits (it waits on `status.probing.Wait()`).

With many concurrent targets, this can exhaust all file descriptors and goroutines.

### Scenario B: Race-induced incorrect DANE assessment (DNS-1)

1. `smtpdane` probes multiple targets concurrently, each triggering DNS resolution.
2. One DNS server returns truncated UDP responses (valid behaviour for large DNSSEC-signed zones).
3. One goroutine sets `c.Net = "tcp"` on the shared `*dns.Client`.
4. Another goroutine, mid-query with `c.Net = "udp"`, now has its transport silently changed.
5. The second goroutine retries its UDP query over TCP but with the wrong query state, producing
   an error that is reported as "no TLSA records" or a resolution failure.

### Scenario C: TLS handshake deadlock via certificate flooding (DANE-1)

1. A server is configured with many TLSA records in DNS (requires DNS control or poisoning).
2. The server also presents a long certificate chain (> 64 / number-of-TLSA-records intermediates).
3. `peerCertificateVerifier` matches many `(TLSA, caCert)` pairs, writing 65+ items to `ch`.
4. The 65th write blocks because `ch` is full and the drain goroutine hasn't started yet.
5. The TLS handshake never completes; the drain goroutine never starts; permanent deadlock.

---

## Recommended Fixes

### Fix SMTP-1: Per-operation deadline {#fix-smtp-1}

**Files:** `common.go`, `main.go`, `probe.go`

Add `operationTimeout time.Duration` to the `opts` struct in `common.go`. Register a
`-operation-timeout` flag in `main.go` (default `30s`). In `probeConnectedAddr()`, set a deadline
on the raw connection before any protocol work:

```go
// probe.go — at the top of probeConnectedAddr(), after verifier setup
if opts.operationTimeout > 0 {
    conn.SetDeadline(time.Now().Add(opts.operationTimeout))
}
```

This single `SetDeadline` covers all subsequent reads and writes on `conn` because `net/smtp`,
`crypto/tls`, and `net/textproto` all operate on the same underlying `net.Conn`. When the deadline
fires, all blocked operations return `net.Error` with `Timeout() == true`, which the existing error
handling correctly reports.

---

### Fix DNS-1: Per-call dns.Client {#fix-dns-1}

**File:** `resolve.go`

Replace the shared-singleton pattern with a local `*dns.Client` per call to
`resolveRRmaybeSecure()`:

```go
// At top of resolveRRmaybeSecure(), after initDNS():
c := &dns.Client{
    Net:     "udp",
    Timeout: time.Duration(config.Timeout) * time.Second,
}
```

All mutations of `c.Net` then operate on a goroutine-local struct. The `dnsSettings.client` field
becomes unused and can be removed, or retained only as a source of timeout configuration.

---

### Fix DANE-1: Unbounded collector goroutine {#fix-dane-1}

**File:** `dane.go`

In `peerCertificateVerifierFor()`, replace the single 64-slot channel with an internal buffer
goroutine:

```go
internal := make(chan certDetails, 64)
external := make(chan certDetails)
go func() {
    var collected []certDetails
    for cd := range internal {
        collected = append(collected, cd)
    }
    for _, cd := range collected {
        external <- cd
    }
    close(external)
}()
```

The verifier writes to `internal` (non-blocking for the first 64, buffered to reduce goroutine
wakes). The collector goroutine accumulates all items. When the verifier closes `internal` (via
`defer close(chCertDetails)` — now `defer close(internal)`), the collector re-emits to `external`
and closes it. `checkCertInfo` reads from `external` as before. The TLS handshake can now always
complete because `internal` never blocks permanently.

---

### Fix DNS-2: Log CNAME records {#fix-dns-2}

**File:** `resolve.go`

Replace the silent skip with a debug log:

```go
for _, rr := range r.Answer {
    if rr.Header().Rrtype == dns.TypeCNAME {
        debugf("CNAME in answer section for %s, skipping (not following)\n", rrname)
        continue
    }
    if rr.Header().Rrtype != typ {
        continue
    }
    ...
}
```

---

### Fix CODE-1: filepath.Join {#fix-code-1}

**File:** `known_certs.go`

```go
// Before:
data, err := os.ReadFile(directory + "/" + entry.Name())

// After:
data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
```

Add `"path/filepath"` to the import block.

---

## Test Coverage Gaps

Prior to this audit, the test suite covered only the happy-path TLS-on-connect scenario
(`TestProbeTLSOnConnect`). The STARTTLS path (`BrokenTestProbeConnection`) was disabled due to a
TLS teardown hang — which is itself a symptom of SMTP-1.

### Gaps addressed by the new test suite

| Test file | Covers |
|---|---|
| `timeout_test.go` | All SMTP-1 stall scenarios (pre-banner, post-banner, post-EHLO, TLS handshake) |
| `security_regression_test.go` | DNS-1 race, DANE-1 deadlock, DNS-2 CNAME, CODE-1 path, regressions |
| `dns_mock_test.go` | DNS resolver injection infrastructure |
| `malicious_server_test.go` | In-memory malicious SMTP server harness |

### Remaining gaps (out of scope for this audit)

- DNSSEC validation is not locally tested (DNS-3); depends on resolver behaviour.
- Proxy path (`probeProxiedAddr`) has no test coverage.
- MX/SRV lookup paths are lightly tested; only the direct host path is well covered.
- Large certificate chains (memory exhaustion path) are not fuzz-tested.

---

*End of security audit.*
