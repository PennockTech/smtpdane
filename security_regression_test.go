// Copyright © 2024 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// --- DNS-1: Data race on dns.Client.Net ---

// TestDNSClientNetRace verifies there is no data race when multiple goroutines
// call ResolveAddrINSECURE concurrently.  Run with -race to detect the race.
//
// The fix (per-call dns.Client) removes the shared singleton mutation.
func TestDNSClientNetRace(t *testing.T) {
	// Use a mock DNS resolver that returns a truncated response first (forcing
	// the Net field to be switched to "tcp") and a normal response second.
	var callCount int32
	testResolverOverride = func(m *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
		n := atomic.AddInt32(&callCount, 1)
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Rcode = dns.RcodeSuccess
		resp.AuthenticatedData = false
		if n%2 == 1 {
			// Odd calls: truncated, to force tcp retry.
			resp.Truncated = true
		} else {
			// Even calls: real A answer.
			resp.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   m.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: net.ParseIP("192.0.2.1").To4(),
				},
			}
		}
		return resp, 0, nil
	}
	defer func() { testResolverOverride = nil }()

	const N = 10
	var wg sync.WaitGroup
	for range N {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// ResolveAddrINSECURE triggers the c.Net = "udp" mutation.
			_, _ = ResolveAddrINSECURE("mail.race-test.invalid")
		}()
	}
	wg.Wait()
}

// --- DANE-1: certDetails channel does not deadlock with many chains ---

// TestCertChannelNoDeadlockWith65Chains verifies that the certDetails channel
// does not deadlock when the verifier would need to send ≥65 items.
//
// We simulate this by creating a validationContext with 65 DANE-EE TLSA records
// that all match the test server certificate.  The verifier would send 65 items.
// Without the fix the TLS handshake deadlocks; with the fix it completes.
func TestCertChannelNoDeadlockWith65Chains(t *testing.T) {
	opts.operationTimeout = 3 * time.Second
	defer func() { opts.operationTimeout = 0 }()

	hostname := "mail.test.invalid"
	// Build 65 DANE-EE TLSA records, all matching the test server cert.
	baseTLSAs := hostnameToTLSArecords[hostname]
	manyTLSAs := make([]*dns.TLSA, 0, 65)
	for len(manyTLSAs) < 65 {
		manyTLSAs = append(manyTLSAs, baseTLSAs...)
	}
	manyTLSAs = manyTLSAs[:65]

	vc, messages := newTestValidationContext(hostname)
	vc.tlsaSet = &TLSAset{
		RRs:       manyTLSAs,
		name:      hostname,
		foundName: hostname,
	}

	opts.tlsOnConnect = true
	defer func() { opts.tlsOnConnect = false }()
	vc.port = 465

	conn := newTestSMTPServer(t, hostname, true)

	done := make(chan struct{})
	go func() {
		vc.probeConnectedAddr(conn)
		close(messages)
		close(done)
	}()
	for range messages {
	}

	select {
	case <-done:
		// completed without deadlock
	case <-time.After(5 * time.Second):
		t.Error("probe deadlocked — certDetails channel not drained (DANE-1 not fixed)")
	}
}

// --- DNS-2: CNAME in answer section does not crash ---

// TestCNAMEInAnswerSectionNoCrash verifies that a CNAME record returned in
// the answer section (alongside or instead of the requested type) does not
// cause a panic or unexpected failure mode.
func TestCNAMEInAnswerSectionNoCrash(t *testing.T) {
	answers := map[string]mockDNSAnswer{
		"mail.cname-test.invalid./A": {
			rrs: []dns.RR{
				// Return a CNAME instead of an A record — triggers the TODO: CNAME? path.
				newMockCNAME("mail.cname-test.invalid.", "target.cname-test.invalid."),
			},
			authenticated: true,
			rcode:         dns.RcodeSuccess,
		},
		"mail.cname-test.invalid./AAAA": {
			// NXDOMAIN for AAAA
			rcode: dns.RcodeNameError,
		},
	}

	withMockDNS(answers, func() {
		// Should not panic; may return an error (no results found is fine)
		addrs, err := ResolveAddrINSECURE("mail.cname-test.invalid")
		if err == nil && len(addrs) == 0 {
			// acceptable: empty result
		} else if err != nil {
			t.Logf("ResolveAddrINSECURE returned expected error: %v", err)
		}
		// The key assertion: we got here without panicking.
	})
}

// --- CODE-1: filepath.Join equivalence ---

// TestFilepathJoinEquivalence verifies that loadKnownCAs can load certificates
// from a temp directory, exercising the directory-scan path in known_certs.go.
func TestFilepathJoinEquivalence(t *testing.T) {
	// Create a temp dir with a PEM cert file.
	dir := t.TempDir()
	certFile := filepath.Join(dir, "test-ca.pem")
	if err := os.WriteFile(certFile, dataCACert, 0644); err != nil {
		t.Fatalf("write temp cert: %v", err)
	}

	t.Setenv("SSL_CERT_DIR", dir)
	t.Setenv("SSL_CERT_FILE", "") // clear the file env so dir is used

	known := loadKnownCAs()
	if known == nil {
		t.Error("loadKnownCAs returned nil — directory traversal may have failed")
		return
	}
	if len(known.certs) == 0 {
		t.Error("loadKnownCAs returned empty cert map — cert file was not loaded")
	}
}

// --- Regression: basic DNS functionality with mock resolver ---

// TestMXLookupResolvesCorrectly verifies that ResolveMX returns expected results
// when backed by the mock resolver.
func TestMXLookupResolvesCorrectly(t *testing.T) {
	answers := map[string]mockDNSAnswer{
		"example.test.invalid./MX": {
			rrs: []dns.RR{
				&dns.MX{
					Hdr: dns.RR_Header{
						Name:   "example.test.invalid.",
						Rrtype: dns.TypeMX,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Preference: 10,
					Mx:         "mail.example.test.invalid.",
				},
			},
			authenticated: true,
			rcode:         dns.RcodeSuccess,
		},
	}

	withMockDNS(answers, func() {
		hosts, err := ResolveMX("example.test.invalid")
		if err != nil {
			t.Errorf("ResolveMX returned unexpected error: %v", err)
			return
		}
		if len(hosts) != 1 || hosts[0] != "mail.example.test.invalid." {
			t.Errorf("ResolveMX returned unexpected result: %v", hosts)
		}
	})
}

// TestTLSALookupRequiresDNSSEC verifies that ResolveTLSA fails when the AD bit
// is not set in the DNS response (DNSSEC not authenticated).
func TestTLSALookupRequiresDNSSEC(t *testing.T) {
	tlsaName := "_25._tcp.mail.dnssec-test.invalid."
	answers := map[string]mockDNSAnswer{
		tlsaName + "/TLSA": {
			rrs: []dns.RR{
				newMockTLSA("_25._tcp.mail.dnssec-test.invalid", 3, 1, 1,
					"aabbccdd"),
			},
			authenticated: false, // AD bit not set
			rcode:         dns.RcodeSuccess,
		},
	}

	withMockDNS(answers, func() {
		_, err := ResolveTLSA("mail.dnssec-test.invalid", 25)
		if err == nil {
			t.Error("ResolveTLSA should have failed when AD bit is not set")
		} else {
			t.Logf("correctly rejected non-AD response: %v", err)
		}
	})
}

// TestNonADResponseRejected verifies that a DNS response without the AD bit
// is rejected for secure resolution paths.
func TestNonADResponseRejected(t *testing.T) {
	answers := map[string]mockDNSAnswer{
		"mail.insecure-test.invalid./A": {
			rrs: []dns.RR{
				newMockA("mail.insecure-test.invalid.", "192.0.2.42"),
			},
			authenticated: false, // No AD bit
			rcode:         dns.RcodeSuccess,
		},
	}

	withMockDNS(answers, func() {
		_, _, err := ResolveAddrSecure("mail.insecure-test.invalid")
		if err == nil {
			t.Error("ResolveAddrSecure should have failed with non-AD response")
		} else {
			t.Logf("correctly rejected non-AD response: %v", err)
		}
	})
}

// TestTruncatedResponseRetriesViaTCP verifies that a truncated UDP response
// triggers a TCP retry (without racing on the dns.Client.Net field).
func TestTruncatedResponseRetriesViaTCP(t *testing.T) {
	callCount := 0
	testResolverOverride = func(m *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
		callCount++
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Rcode = dns.RcodeSuccess
		resp.AuthenticatedData = false

		if callCount == 1 {
			// First call: truncated
			resp.Truncated = true
			return resp, 0, nil
		}
		// Second call (TCP retry): real answer
		resp.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   m.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP("192.0.2.99").To4(),
			},
		}
		return resp, 0, nil
	}
	defer func() { testResolverOverride = nil }()

	addrs, err := ResolveAddrINSECURE("mail.tcp-retry-test.invalid")
	if err != nil {
		t.Errorf("expected successful resolution after TCP retry, got: %v", err)
	}
	if callCount < 2 {
		t.Errorf("expected at least 2 DNS calls (truncated + retry), got %d", callCount)
	}
	if len(addrs) == 0 {
		t.Error("expected at least one address after TCP retry")
	} else {
		t.Logf("resolved %d address(es): %v", len(addrs), addrs)
	}
}
