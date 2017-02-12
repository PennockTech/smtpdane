// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

// +build go1.8

package main

import (
	"crypto/tls"
	"net"
	"net/smtp"
	"net/textproto"
)

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

	for _, ip := range ipList {
		status.probing.Add(1)
		go probeAddr(ip, hostname, port, status)
	}
}

func probeAddr(ip net.IP, hostname string, port int, status *programStatus) {
	defer status.probing.Done()

	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{ip, port, ""})
	if err != nil {
		status.Errorf("dial failed: %s", err)
		return
	}

	tlsConfig := &tls.Config{
		ServerName:            hostname,
		InsecureSkipVerify:    true, // we verify ourselves in the VerifyPeerCertificate
		VerifyPeerCertificate: nil,  // FIXME
	}

	if opts.tlsOnConnect {
		tryTLSOnConn(conn, hostname, ip, tlsConfig, status)
		return
	}

	s, err := smtp.NewClient(conn, hostname)
	if err != nil {
		status.Errorf("[%s %v] failed to establish SMTP client on connection: %s", hostname, ip, err)
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
		status.Errorf("[%s %v] EHLO failed: %s", hostname, ip, err)
		s.Close()
		return
	}

	ok, _ := s.Extension("STARTTLS")
	if !ok {
		status.Errorf("[%s %v] server does not advertise STARTTLS", hostname, ip)
		s.Close()
		return
	}

	status.Messagef("[%s %v] issuing STARTTLS", hostname, ip)
	err = s.StartTLS(tlsConfig)
	if err != nil {
		status.Errorf("[%s %v] STARTTLS failed: %s", hostname, ip, err)
	}
	err = s.Quit()
	if err != nil {
		status.Errorf("[%s %v] QUIT failed: %s", hostname, ip, err)
	}
	return
}

func tryTLSOnConn(conn net.Conn, hostname string, ip net.IP, tlsConfig *tls.Config, status *programStatus) {
	status.Messagef("[%s %v] starting TLS immediately", hostname, ip)
	c := tls.Client(conn, tlsConfig)
	t := textproto.NewConn(c)

	_, _, err := t.ReadResponse(220)
	if err != nil {
		t.Close()
		status.Errorf("[%s %v] banner read failed: %s", hostname, ip, err)
		return
	}

	id, err := t.Cmd("EHLO %s", hostname)
	t.StartResponse(id)
	_, _, err = t.ReadResponse(250)
	t.EndResponse(id)
	if err != nil {
		status.Errorf("[%s %v] EHLO failed: %s", hostname, ip, err)
	}

	id, err = t.Cmd("QUIT")
	t.StartResponse(id)
	_, _, err = t.ReadResponse(221)
	t.EndResponse(id)
	if err != nil {
		status.Errorf("[%s %v] QUIT failed: %s", hostname, ip, err)
	}
	t.Close()
}
