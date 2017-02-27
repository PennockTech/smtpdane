// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"testing"
)

var hostnameToTLSArecords map[string][]*dns.TLSA
var hostnameToCertChain map[string]tls.Certificate

func init() {
	hostnameToTLSArecords = make(map[string][]*dns.TLSA)
	hostnameToCertChain = make(map[string]tls.Certificate)

	keyCert, err := tls.X509KeyPair(dataServerCert, dataServerKey)
	if err != nil {
		panic("unsigned: " + err.Error())
	}
	chained := make([]byte, 0, len(dataServerCert)+len(dataCACert))
	chained = append(chained, dataServerCert...)
	chained = append(chained, dataCACert...)

	signedKeyCert, err := tls.X509KeyPair(chained, dataServerKey)
	if err != nil {
		panic("ca-signed: " + err.Error())
	}

	hostnameToTLSArecords["mail.test.invalid"] = []*dns.TLSA{
		dataCATLSACert, dataCATLSAPubkey, dataSvrTLSACert, dataSvrTLSAPubkey,
	}
	hostnameToCertChain["mail.test.invalid"] = signedKeyCert
	hostnameToTLSArecords["signedok.test.invalid"] = []*dns.TLSA{dataCATLSACert, dataCATLSAPubkey}
	hostnameToCertChain["signedok.test.invalid"] = signedKeyCert
	hostnameToTLSArecords["unsigned.test.invalid"] = []*dns.TLSA{dataSvrTLSACert, dataSvrTLSAPubkey}
	hostnameToCertChain["unsigned.test.invalid"] = keyCert

	for hn := range hostnameToTLSArecords {
		for i := range hostnameToTLSArecords[hn] {
			hostnameToTLSArecords[hn][i].Hdr.Name = hn
			hostnameToTLSArecords[hn][i].Hdr.Rrtype = dns.TypeTLSA
			hostnameToTLSArecords[hn][i].Hdr.Class = dns.ClassINET
			hostnameToTLSArecords[hn][i].Hdr.Ttl = 600
			hostnameToTLSArecords[hn][i].Hdr.Rdlength = uint16(3 + len(hostnameToTLSArecords[hn][i].Certificate)/2)
		}
	}

}

func newTestValidationContext(hostname string) (validationContext, chan string) {
	messages := make(chan string)
	vc := validationContext{
		hostname: hostname,
		altNames: nil,
		ip:       net.ParseIP("192.0.2.25"),
		port:     25,
		status: &programStatus{
			probing: &sync.WaitGroup{},
			output:  messages,
		},
		time: time.Now(),
		tlsaSet: &TLSAset{
			RRs:       hostnameToTLSArecords[hostname],
			name:      hostname,
			foundName: hostname,
		},
	}
	return vc, messages
}

type smtpSender struct {
	w io.Writer
}

func (s smtpSender) sendf(spec string, args ...interface{}) {
	fmt.Fprintf(s.w, spec+"\r\n", args...)
}

func newTestSMTPServer(t *testing.T, hostname string, tlsOnConnect bool) net.Conn {
	svrTLS, ok := hostnameToCertChain[hostname]
	if !ok {
		t.Fatalf("no server config available for host %q", hostname)
		return nil // not-reached
	}
	clConn, svrConn := net.Pipe()

	// chunks of this bit ripped from net/smtp/smtp_test.go
	go func(c net.Conn, hostname string, tlsCert tls.Certificate, tlsOnConnect bool, t *testing.T) {
		inTLS := false
		sendf := smtpSender{c}.sendf
		if tlsOnConnect {
			config := &tls.Config{Certificates: []tls.Certificate{tlsCert}}
			c = tls.Server(c, config)
			sendf = smtpSender{c}.sendf
			inTLS = true
		}
		sendf("220 %s ESMTP mock ready", hostname)
		s := bufio.NewScanner(c)
	RESTART_SCAN:
		for s.Scan() {
			cmd := s.Text()
			verb := strings.ToUpper(strings.Fields(cmd)[0])
			rest := strings.TrimSpace(cmd[len(verb):])
			switch verb {
			case "EHLO":
				t.Logf("EHLO seen from %q", rest)
				// unchecked index; ok for test
				sendf("250-%s ESMTP offers a warm hug of welcome to %s", hostname, rest)
				if !inTLS {
					sendf("250-STARTTLS")
				}
				sendf("250 Ok")
			case "STARTTLS":
				if inTLS {
					t.Error("Got STARTTLS inside TLS session")
					sendf("503 STARTTLS command used when not advertised")
					continue
				}
				sendf("220 Go ahead")
				config := &tls.Config{Certificates: []tls.Certificate{tlsCert}}
				c = tls.Server(c, config)
				sendf = smtpSender{c}.sendf
				s = bufio.NewScanner(c)
				goto RESTART_SCAN
			case "QUIT":
				sendf("221 %s closing connection", hostname)
				if err := c.Close(); err != nil {
					t.Errorf("svr failed to close connection: %s", err)
				}
				return
			default:
				if err := c.Close(); err != nil {
					t.Errorf("svr failed to close connection: %s", err)
				}
				t.Fatalf("unrecognized command: %q", s.Text())
			}
		}
		t.Log("lost connection without QUIT?")
		if err := c.Close(); err != nil {
			t.Errorf("svr failed to close connection: %s", err)
		}
	}(svrConn, hostname, svrTLS, tlsOnConnect, t)

	return clConn
}

func TestProbeConnection(t *testing.T) {
	vc, messages := newTestValidationContext("mail.test.invalid")
	conn := newTestSMTPServer(t, "mail.test.invalid", false)

	go func(ms chan<- string) {
		vc.probeConnectedAddr(conn)
		close(ms)
	}(messages)

	for msg := range messages {
		t.Log(msg)
	}
}

func TestProbeTLSOnConnect(t *testing.T) {
	opts.tlsOnConnect = true
	defer func() { opts.tlsOnConnect = false }()
	vc, messages := newTestValidationContext("mail.test.invalid")
	vc.port = 465
	conn := newTestSMTPServer(t, "mail.test.invalid", true)

	go func(ms chan<- string) {
		vc.probeConnectedAddr(conn)
		close(ms)
	}(messages)

	for msg := range messages {
		t.Log(msg)
	}
}

// See testdata/ dir for origin of these items

var dataServerKey = []byte(`-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHzBEzGDQ+SXegUXi0U3lhmOp0gzqWCM02SQlOwCHD86oAoGCCqGSM49
AwEHoUQDQgAEnjQBytIbEYQsIT6KqW4g7b/FAVhPMiHMJzQuRxfbPJmjGXbgdhat
0KIs9gIjMp6vlCdqza5zAMR8gfl1rMIheA==
-----END EC PRIVATE KEY-----
`)

// valid for: DNS:mail.test.invalid, DNS:signedok.test.invalid, DNS:unsigned.test.invalid
var dataServerCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDLTCCArKgAwIBAgIBQjAKBggqhkjOPQQDAjBgMQswCQYDVQQGEwJVUzEQMA4G
A1UECgwHRXhhbXBsZTESMBAGA1UECwwJU01UUC1EQU5FMSswKQYDVQQDDCJEdW1t
eSB1bnRydXN0d29ydGh5IENBIGZvciB0ZXN0aW5nMB4XDTE3MDIyNzAyMzU0MVoX
DTM3MDIyMjAyMzU0MVowHDEaMBgGA1UEAxMRbWFpbC50ZXN0LmludmFsaWQwWTAT
BgcqhkjOPQIBBggqhkjOPQMBBwNCAASeNAHK0hsRhCwhPoqpbiDtv8UBWE8yIcwn
NC5HF9s8maMZduB2Fq3Qoiz2AiMynq+UJ2rNrnMAxHyB+XWswiF4o4IBnzCCAZsw
CQYDVR0TBAIwADBHBglghkgBhvhCAQ0EOhY4RHVtbXkgdW50cnVzdHdvcnRoeSBU
TFMgc2VydmVyIGNlcnRpZmljYXRlIGZvciBTTVRQIERBTkUwHQYDVR0OBBYEFHR+
v4bGn8ZF8o6CLBC+o+3kS/6wMIGNBgNVHSMEgYUwgYKAFIX2dctBQZ3DtJmgxNOy
Jnezxc8uoWSkYjBgMQswCQYDVQQGEwJVUzEQMA4GA1UECgwHRXhhbXBsZTESMBAG
A1UECwwJU01UUC1EQU5FMSswKQYDVQQDDCJEdW1teSB1bnRydXN0d29ydGh5IENB
IGZvciB0ZXN0aW5nggQBI0VnMAsGA1UdDwQEAwIFoDAqBgNVHSUEIzAhBggrBgEF
BQcDAQYJYIZIAYb4QgQBBgorBgEEAYI3CgMDMBEGCWCGSAGG+EIBAQQEAwIGQDBK
BgNVHREEQzBBghFtYWlsLnRlc3QuaW52YWxpZIIVc2lnbmVkb2sudGVzdC5pbnZh
bGlkghV1bnNpZ25lZC50ZXN0LmludmFsaWQwCgYIKoZIzj0EAwIDaQAwZgIxAJPn
huCyG+m0Pm++fA0WcQiYLOKc3Z76mxzkSQScJGF5VxQ6mIkRIwnXAlhjFSckjgIx
AI5kYo7ADwtrn0GrFjhAoFhhG86Btf/s8UsrNiSsJ3tV5SHrBLfBH9fpTX3cnN/O
0A==
-----END CERTIFICATE-----
`)

// see testdata dir
var dataCACert = []byte(`-----BEGIN CERTIFICATE-----
MIICQDCCAcWgAwIBAgIEASNFZzAKBggqhkjOPQQDAjBgMQswCQYDVQQGEwJVUzEQ
MA4GA1UECgwHRXhhbXBsZTESMBAGA1UECwwJU01UUC1EQU5FMSswKQYDVQQDDCJE
dW1teSB1bnRydXN0d29ydGh5IENBIGZvciB0ZXN0aW5nMB4XDTE3MDIyNzAxNTQ1
NVoXDTM3MDIyMjAxNTQ1NVowYDELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0V4YW1w
bGUxEjAQBgNVBAsMCVNNVFAtREFORTErMCkGA1UEAwwiRHVtbXkgdW50cnVzdHdv
cnRoeSBDQSBmb3IgdGVzdGluZzB2MBAGByqGSM49AgEGBSuBBAAiA2IABEgtXo6w
90cuBld6FIiMBWqypI/6f9hl61z1acWya510E0yS+n7nHLKwQx2mqlWhxU3dRGJT
J/QV3gZXjXtOidRUJnDbRurAULPZWt/DMgnjTY9kIZ903oiy48florhPsqNQME4w
HQYDVR0OBBYEFIX2dctBQZ3DtJmgxNOyJnezxc8uMB8GA1UdIwQYMBaAFIX2dctB
QZ3DtJmgxNOyJnezxc8uMAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDaQAwZgIx
ANB6krUHooFqJU7FlmknUmdEQtjOOxPefLTSUnuOXUxihIPy+gg92+R7txCEc+62
tQIxAOR3uqu4gOoXm08N/GUGq8hdUPsCa39DcikuksToLJFnqld1BjNkr+lZeFG0
Sa4xHw==
-----END CERTIFICATE-----
`)

var dataCATLSACert = &dns.TLSA{dns.RR_Header{}, 2, 0, 1, "e348526e32d604c1ca313637940ae1035da6055039890de9863885403cd34f63"}
var dataCATLSAPubkey = &dns.TLSA{dns.RR_Header{}, 2, 1, 1, "c6959b48dd7a09d1f3e2dba1b8c308a5821244d34fa6484c4b2dfb141a23b6e4"}
var dataSvrTLSACert = &dns.TLSA{dns.RR_Header{}, 3, 0, 1, "78da6f10cdccd9775872ff871178748df22fcbe6ad66d9d744737cb0e9fa9b3c"}
var dataSvrTLSAPubkey = &dns.TLSA{dns.RR_Header{}, 3, 1, 1, "9a8079b2bfff4b8250cdeadfe26a406f27d79d5b1a15ed9310c240cb5bd9de27"}
