// Copyright © 2024 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"net"
	"testing"
	"time"
)

// stallTestTimeout is how long we wait for a stall test to complete.
// It must be comfortably larger than opts.operationTimeout in these tests.
const stallTestTimeout = 5 * time.Second

// runWithTimeout runs fn in a goroutine and fails the test if it doesn't
// complete within d.
func runWithTimeout(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
		// ok
	case <-time.After(d):
		t.Errorf("probe did not complete within %v (expected per-operation timeout to fire)", d)
	}
}

// newStallValidationContext builds a validationContext for stall tests.
// It uses the well-known test certificate data from tls_test.go.
func newStallValidationContext(t *testing.T) (validationContext, chan string) {
	t.Helper()
	vc, messages := newTestValidationContext("mail.test.invalid")
	return vc, messages
}

// probeConnAndDrain calls probeConnectedAddr on conn and drains messages.
func probeConnAndDrain(vc validationContext, conn net.Conn, messages chan string) {
	go func() {
		vc.probeConnectedAddr(conn)
		close(messages)
	}()
	for range messages {
	}
}

// --- STARTTLS path stall tests ---

// TestSTARTTLSHangsBeforeBanner verifies that the tool does not hang forever
// when a server accepts TCP but never sends the 220 greeting.
// Requires SMTP-1 fix (conn.SetDeadline) to pass.
func TestSTARTTLSHangsBeforeBanner(t *testing.T) {
	opts.operationTimeout = 500 * time.Millisecond
	defer func() { opts.operationTimeout = 0 }()

	vc, messages := newStallValidationContext(t)
	conn := newMaliciousSMTPServer(t, "mail.test.invalid", StallBeforeBanner)

	runWithTimeout(t, stallTestTimeout, func() {
		probeConnAndDrain(vc, conn, messages)
	})
}

// TestSTARTTLSHangsAfterBanner verifies that the tool does not hang when a
// server sends the 220 greeting but never responds to EHLO.
func TestSTARTTLSHangsAfterBanner(t *testing.T) {
	opts.operationTimeout = 500 * time.Millisecond
	defer func() { opts.operationTimeout = 0 }()

	vc, messages := newStallValidationContext(t)
	conn := newMaliciousSMTPServer(t, "mail.test.invalid", StallAfterBanner)

	runWithTimeout(t, stallTestTimeout, func() {
		probeConnAndDrain(vc, conn, messages)
	})
}

// TestSTARTTLSHangsAfterEHLO verifies that the tool does not hang when a
// server completes the EHLO exchange but never responds to STARTTLS.
func TestSTARTTLSHangsAfterEHLO(t *testing.T) {
	opts.operationTimeout = 500 * time.Millisecond
	defer func() { opts.operationTimeout = 0 }()

	vc, messages := newStallValidationContext(t)
	conn := newMaliciousSMTPServer(t, "mail.test.invalid", StallAfterEHLO)

	runWithTimeout(t, stallTestTimeout, func() {
		probeConnAndDrain(vc, conn, messages)
	})
}

// TestSTARTTLSHandshakeStall verifies that the tool does not hang when a
// server sends "220 Go ahead" but never completes the TLS handshake.
func TestSTARTTLSHandshakeStall(t *testing.T) {
	opts.operationTimeout = 500 * time.Millisecond
	defer func() { opts.operationTimeout = 0 }()

	vc, messages := newStallValidationContext(t)
	conn := newMaliciousSMTPServer(t, "mail.test.invalid", StallAfterSTARTTLSReply)

	runWithTimeout(t, stallTestTimeout, func() {
		probeConnAndDrain(vc, conn, messages)
	})
}

// --- TLS-on-connect path stall tests ---

// TestTLSOnConnectTLSHandshakeStall verifies that the tool does not hang when
// a TLS-on-connect server sends a partial TLS record then stalls.
func TestTLSOnConnectTLSHandshakeStall(t *testing.T) {
	opts.tlsOnConnect = true
	opts.operationTimeout = 500 * time.Millisecond
	defer func() {
		opts.tlsOnConnect = false
		opts.operationTimeout = 0
	}()

	vc, messages := newStallValidationContext(t)
	vc.port = 465
	conn := newMaliciousTLSOnConnectServer(t, "mail.test.invalid", StallDuringTLSHandshake)

	runWithTimeout(t, stallTestTimeout, func() {
		probeConnAndDrain(vc, conn, messages)
	})
}

// TestTLSOnConnectBannerStall verifies that the tool does not hang when a
// TLS-on-connect server completes the TLS handshake but never sends the banner.
func TestTLSOnConnectBannerStall(t *testing.T) {
	opts.tlsOnConnect = true
	opts.operationTimeout = 500 * time.Millisecond
	defer func() {
		opts.tlsOnConnect = false
		opts.operationTimeout = 0
	}()

	vc, messages := newStallValidationContext(t)
	vc.port = 465
	conn := newMaliciousTLSOnConnectServer(t, "mail.test.invalid", StallAfterTLSBanner)

	runWithTimeout(t, stallTestTimeout, func() {
		probeConnAndDrain(vc, conn, messages)
	})
}

// TestProbeConnection re-enables BrokenTestProbeConnection from tls_test.go.
// The SMTP-1 fix (SetDeadline) resolves the TLS teardown hang that caused it
// to be disabled originally.
func TestProbeConnection(t *testing.T) {
	opts.operationTimeout = 2 * time.Second
	defer func() { opts.operationTimeout = 0 }()

	vc, messages := newTestValidationContext("mail.test.invalid")
	conn := newTestSMTPServer(t, "mail.test.invalid", false)

	go func() {
		vc.probeConnectedAddr(conn)
		close(messages)
	}()

	for msg := range messages {
		t.Log(msg)
	}
}
