// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

// +build go1.8

package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
)

type validationContext struct {
	tlsaSet  *TLSAset
	hostname string
	ip       net.IP
	port     int
	status   *programStatus
}

func (vc validationContext) Messagef(spec string, params ...interface{}) {
	vc.status.Message(fmt.Sprintf("[%s %v] ", vc.hostname, vc.ip) + fmt.Sprintf(spec, params...))
}

func (vc validationContext) Errorf(spec string, params ...interface{}) {
	vc.Messagef(spec, params...)
	vc.status.AddErr()
}

// probeHost is the top-level function of a go-routine and is responsible for
// probing one remote SMTP connection.
//
// Messages should be reported via the Output function of the status; newlines
// are appended and each string is guaranteed to be emitted with no
// interweaving of other results within the string.
func probeHost(hostSpec string, status *programStatus) {
	defer status.probing.Done()

	hostname, port, err := HostnamePortFrom(hostSpec)
	if err != nil {
		status.Errorf("error parsing %q: %s", hostSpec, err)
		return
	}

	ipList, err := resolveSecure(hostname)
	if err != nil {
		status.Errorf("error resolving %q: %s", hostname, err)
		return
	}

	status.Messagef("found %d addresses for %q: %v", len(ipList), hostname, ipList)

	tlsaSet, err := resolveTLSA(hostname, port)
	if err != nil {
		status.Errorf("error resolving TLSA for %q port %d: %v", hostname, port, err)
		return
	}
	status.Messagef("found %d TLSA records for %q", len(tlsaSet.RRs), tlsaSet.name)

	for _, ip := range ipList {
		status.probing.Add(1)
		go validationContext{
			tlsaSet:  tlsaSet,
			hostname: hostname,
			ip:       ip,
			port:     port,
			status:   status,
		}.probeAddr()
	}
}

func (vc validationContext) probeAddr() {
	defer vc.status.probing.Done()

	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{vc.ip, vc.port, ""})
	if err != nil {
		vc.status.Errorf("dial failed: %s", err)
		return
	}

	tlsConfig := &tls.Config{
		ServerName:            vc.hostname,
		InsecureSkipVerify:    true, // we verify ourselves in the VerifyPeerCertificate
		VerifyPeerCertificate: peerCertificateVerifierFor(vc),
	}

	if opts.tlsOnConnect {
		vc.tryTLSOnConn(conn, tlsConfig)
		return
	}

	s, err := smtp.NewClient(conn, vc.hostname)
	if err != nil {
		vc.Errorf("failed to establish SMTP client on connection: %s", err)
		_ = conn.Close()
		return
	}

	// TODO: figure out a sane timeout mechanism (which also handles pre-banner
	// delays) or some other mechanism to handle Golang net/smtp just hanging
	// when given a TLS-on-connect server (which is reasonable, since for TLS,
	// client-speaks-first and the SMTP code is just waiting for the server to
	// speak).
	err = s.Hello(opts.heloName)
	if err != nil {
		vc.Errorf("EHLO failed: %s", err)
		s.Close()
		return
	}

	ok, _ := s.Extension("STARTTLS")
	if !ok {
		vc.Errorf("server does not advertise STARTTLS")
		s.Close()
		return
	}

	vc.Messagef("issuing STARTTLS")
	err = s.StartTLS(tlsConfig)
	if err != nil {
		vc.Errorf("STARTTLS failed: %s", err)
	}
	err = s.Quit()
	if err != nil {
		vc.Errorf("QUIT failed: %s", err)
	}
	return
}

func (vc validationContext) tryTLSOnConn(conn net.Conn, tlsConfig *tls.Config) {
	vc.Messagef("starting TLS immediately")
	c := tls.Client(conn, tlsConfig)
	t := textproto.NewConn(c)

	_, _, err := t.ReadResponse(220)
	if err != nil {
		t.Close()
		vc.Errorf("banner read failed: %s", err)
		return
	}

	id, err := t.Cmd("EHLO %s", vc.hostname)
	t.StartResponse(id)
	_, _, err = t.ReadResponse(250)
	t.EndResponse(id)
	if err != nil {
		vc.Errorf("EHLO failed: %s", err)
	}

	id, err = t.Cmd("QUIT")
	t.StartResponse(id)
	_, _, err = t.ReadResponse(221)
	t.EndResponse(id)
	if err != nil {
		vc.Errorf("QUIT failed: %s", err)
	}
	t.Close()
}
