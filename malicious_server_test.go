// Copyright © 2024 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"testing"
)

// SMTPStallPoint enumerates the points in the SMTP exchange where a malicious
// server can stall.
type SMTPStallPoint int

const (
	// StallBeforeBanner: server accepts TCP but never sends the 220 greeting.
	StallBeforeBanner SMTPStallPoint = iota
	// StallAfterBanner: server sends 220, then goes silent (no response to EHLO).
	StallAfterBanner
	// StallAfterEHLO: server sends 220 + EHLO response, then stops.
	StallAfterEHLO
	// StallAfterSTARTTLSReply: server sends "220 Go ahead", then stalls (no TLS handshake).
	StallAfterSTARTTLSReply
	// StallDuringTLSHandshake: server starts TLS but sends partial data, blocking.
	StallDuringTLSHandshake
	// StallAfterTLSBanner: for TLS-on-connect — TLS handshake completes but no banner.
	StallAfterTLSBanner
)

// stallingServer is the server side of a pipe-based test SMTP server.
type stallingServer struct {
	c net.Conn
}

func (s *stallingServer) sendf(format string, args ...any) {
	fmt.Fprintf(s.c, format+"\r\n", args...)
}

func (s *stallingServer) readLine() {
	buf := make([]byte, 512)
	s.c.Read(buf) //nolint:errcheck
}

// drain holds the server side open indefinitely (until the pipe is closed by
// the test), simulating a stalling server.
func (s *stallingServer) drain() {
	buf := make([]byte, 1024)
	for {
		_, err := s.c.Read(buf)
		if err != nil {
			return
		}
	}
}

// newMaliciousSMTPServer creates an in-memory pipe-based SMTP server that stalls
// at the specified point in the STARTTLS (port-25) flow.
// The client-side net.Conn is returned for use with probeConnectedAddr.
func newMaliciousSMTPServer(t *testing.T, hostname string, stallAt SMTPStallPoint) net.Conn {
	t.Helper()
	clConn, svrConn := net.Pipe()

	go func() {
		svr := &stallingServer{c: svrConn}
		switch stallAt {
		case StallBeforeBanner:
			// Send nothing — hold connection open.

		case StallAfterBanner:
			svr.sendf("220 %s ESMTP stalling mock", hostname)
			// Never respond to EHLO.

		case StallAfterEHLO:
			svr.sendf("220 %s ESMTP stalling mock", hostname)
			svr.readLine() // EHLO
			svr.sendf("250-%s ESMTP offers a warm hug", hostname)
			svr.sendf("250-STARTTLS")
			svr.sendf("250 Ok")
			// Never respond to STARTTLS.

		case StallAfterSTARTTLSReply:
			svr.sendf("220 %s ESMTP stalling mock", hostname)
			svr.readLine() // EHLO
			svr.sendf("250-%s ESMTP offers a warm hug", hostname)
			svr.sendf("250-STARTTLS")
			svr.sendf("250 Ok")
			svr.readLine() // STARTTLS
			svr.sendf("220 Go ahead")
			// Never start TLS.

		case StallDuringTLSHandshake:
			svr.sendf("220 %s ESMTP stalling mock", hostname)
			svr.readLine() // EHLO
			svr.sendf("250-%s ESMTP offers a warm hug", hostname)
			svr.sendf("250-STARTTLS")
			svr.sendf("250 Ok")
			svr.readLine() // STARTTLS
			svr.sendf("220 Go ahead")
			// Write a single TLS record-type byte then stall.
			svrConn.Write([]byte{0x16}) //nolint:errcheck
		}
		svr.drain()
	}()

	return clConn
}

// newMaliciousTLSOnConnectServer creates a TLS-on-connect server that stalls.
// StallAfterTLSBanner: completes TLS but never sends the 220 banner.
// StallDuringTLSHandshake: writes partial TLS record then stalls.
func newMaliciousTLSOnConnectServer(t *testing.T, hostname string, stallAt SMTPStallPoint) net.Conn {
	t.Helper()

	svrTLS, ok := hostnameToCertChain[hostname]
	if !ok {
		t.Fatalf("no server TLS config for %q", hostname)
		return nil
	}

	clConn, svrConn := net.Pipe()

	go func() {
		svr := &stallingServer{c: svrConn}
		switch stallAt {
		case StallAfterTLSBanner:
			tlsConf := &tls.Config{Certificates: []tls.Certificate{svrTLS}}
			tlsConn := tls.Server(svrConn, tlsConf)
			// Complete TLS handshake, then send nothing.
			_ = tlsConn.Handshake()
			svr.c = tlsConn
			// Never send 220 banner.

		case StallDuringTLSHandshake:
			// Partial TLS ServerHello — client TLS stack will block waiting for more.
			svrConn.Write([]byte{0x16, 0x03, 0x03}) //nolint:errcheck
		}
		svr.drain()
	}()

	return clConn
}
