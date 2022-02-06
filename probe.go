// Copyright © 2017,2018 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

//go:build go1.8
// +build go1.8

package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	// Hash algorithms to be available for validation; any not in stdlib
	// should be optional and not here, but in a build-tag-constraint'ed file
	// which just does the import so that crypto.RegisterHash() is called.
	// Those needed for TLS:
	//   <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18>
	// (so no others pulled in yet)
	_ "crypto/sha256"
	_ "crypto/sha512"

	"golang.org/x/crypto/ocsp"

	"go.pennock.tech/smtpdane/internal/errorlist"
)

type validationContext struct {
	tlsaSet  *TLSAset
	hostname string
	altNames []string
	ip       net.IP
	port     int
	status   *programStatus
	time     time.Time
}

func (vc *validationContext) Messagef(spec string, params ...interface{}) {
	vc.status.Message(fmt.Sprintf("[%s %v] ", vc.hostname, vc.ip) + fmt.Sprintf(spec, params...))
}

func (vc *validationContext) Wafflef(spec string, params ...interface{}) {
	if !opts.terse {
		vc.Messagef(spec, params...)
	}
}

func (vc *validationContext) Warnf(spec string, params ...interface{}) {
	vc.Messagef(ColorYellow(spec), params...)
	vc.status.AddWarning()
}

func (vc *validationContext) Errorf(spec string, params ...interface{}) {
	vc.Messagef(ColorRed(spec), params...)
	vc.status.AddErr()
}

func (vc *validationContext) Successf(spec string, params ...interface{}) {
	vc.Messagef(ColorGreen(spec), params...)
}

// ensure that the child status is created in the parent's go-routine
func probeHostGo(hostSpec string, status *programStatus, otherValidNames ...string) {
	status.probing.Add(1)
	status = status.ChildBatcher("probeHost", hostSpec)
	go probeHost(hostSpec, status, otherValidNames...)
}

func statusErrorReportf(status *programStatus, err error, prefixTemplate string, args ...interface{}) {
	prefix := fmt.Sprintf(prefixTemplate, args...)
	switch e := err.(type) {
	case *errorlist.List:
		if opts.terse {
			status.Errorf("%s: %s", prefix, e.FmtList())
		} else {
			status.Errorf("%s\n%s", prefix, e.FmtIndented())
		}
	default:
		status.Errorf("%s: %s", prefix, err)
	}
}

// probeHost is the top-level function of a go-routine and is responsible for
// probing one remote SMTP connection.
//
// Messages should be reported via the Output function of the status; newlines
// are appended and each string is guaranteed to be emitted with no
// interweaving of other results within the string.
func probeHost(hostSpec string, status *programStatus, otherValidNames ...string) {
	defer status.BatchFinished()

	// RFC 7671 section 7: chase CNAMEs (as long as secure) of Base Domain and
	// try for TLSA there first, but then fall back to the original name if not
	// found.  Only the final name and original name should be tried, not any
	// intermediate CNAMEs if they were chained.
	//
	// MX hostnames are not supposed to be CNAMEs so this _shouldn't_ crop up.
	// But if it does, handle it.  The support is explicitly called out in DANE.

	// CNAMEs for TLSA records within the resolution chain have to be chased
	// securely all the way, there must be complete verifiable trust to the
	// TLSA records.  The only insecurity we have to handle is for the address
	// records, which determine which of exactly two hostnames we use as input
	// for the TLSA record lookup.
	//
	//  mx1.secure.example
	//    -CNAME-> foo.secure.example
	//    -CNAME-> bar.insecure.example
	//    -CNAME-> baz.irrelevant.example     OR -A-> frob.secure-again.example
	//    -A->     192.0.2.10
	//
	//  mx2.secure.example
	//    -CNAME-> nozz.secure-again.example
	//    -A->     192.0.2.20
	//
	// For the mx1 case, even with insecure address resolution, we'll try to
	// look for TLSA records for `mx1.secure.example`.
	// For the mx2 case, `nozz.secure-again.example` is the preferred name, but
	// if no secure records are found, then `mx2.secure.example` is tried too.

	originalHostname, port, err := HostnamePortFrom(hostSpec)
	if err != nil {
		status.Errorf("error parsing %q: %s", hostSpec, err)
		return
	}

	// We might have an MX record which is a CNAME; that's normally not allowed
	// by SMTP but is explicitly covered in the DANE SMTP spec.  If we do have
	// a secure path to the original zone, then we do check below for a TLSA
	// record there.  As long as the TLSA record is secure, we're "good", we have
	// a secure identity to verify.
	ipListIsSecure := true
	ipList, preferredHostname, err := ResolveAddrSecure(originalHostname)
	var resolvedCNAME string
	if err != nil {
		originalErr := err

		resolvedCNAME, err = ResolveCNAME(originalHostname)
		if err != nil {
			// original is insecure too, so we disable DANE because origin domain
			// is unsigned, don't even try TLSA records.
			statusErrorReportf(status, originalErr, "error securely resolving %q", originalHostname)
			return
		}
		// skip handling loops, leave that to the insecure resolution to detect

		ipList, err = ResolveAddrINSECURE(originalHostname)
		if err != nil || len(ipList) == 0 {
			statusErrorReportf(status, originalErr, "error insecurely resolving %q", originalHostname)
			return
		}

		status.Wafflef(ColorYellow("found secure CNAME pointing to insecure DNS, validating under original name: %q"), originalHostname)
		preferredHostname = originalHostname
		ipListIsSecure = false
	}

	// original is a CNAME if preferredHostname != originalHostname or resolvedCNAME != ""
	// resolvedCNAME is set if the final path is insecure
	// preferredHostname is the name to validate:
	//   * the final hostname if secure all the way
	//   * the original hostname if there's an insecure delegation (resolvedCNAME is set)

	if preferredHostname == originalHostname && resolvedCNAME == "" {
		status.Wafflef("found %d secure addresses for %q: %v", len(ipList), originalHostname, ipList)
	} else {
		var targetPrequoted string
		if resolvedCNAME != "" {
			targetPrequoted = strconv.Quote(resolvedCNAME) + "/..."
		} else {
			targetPrequoted = strconv.Quote(preferredHostname)
		}
		if opts.mxLookup {
			// Being generous by not just deeming this an error; still, mark it red
			status.Messagef(ColorRed("VIOLATION: MX hostname is a CNAME: %q -> %s"), originalHostname, targetPrequoted)
		}
		var nature string
		if ipListIsSecure {
			nature = "secure"
		} else {
			nature = ColorRed("INSECURE")
		}
		status.Wafflef("found %d %s addresses for %q at %s: %v", len(ipList), nature, originalHostname, targetPrequoted, ipList)
	}

	tlsaSet, err := ResolveTLSA(preferredHostname, port)
	if err != nil {
		statusErrorReportf(status, err, "error resolving TLSA for %q port %d", preferredHostname, port)
		if originalHostname == preferredHostname {
			return
		}
		tlsaSet, err = ResolveTLSA(originalHostname, port)
		if err != nil {
			statusErrorReportf(status, err, "error resolving TLSA for pre-CNAME %q port %d", originalHostname, port)
			return
		}
	}

	tlsaLines := make([]string, 1+len(tlsaSet.RRs))
	if tlsaSet.name == tlsaSet.foundName {
		tlsaLines[0] = fmt.Sprintf("found %d TLSA records for %q", len(tlsaSet.RRs), tlsaSet.name)
	} else {
		tlsaLines[0] = fmt.Sprintf("found %d TLSA records for %q at %q", len(tlsaSet.RRs), tlsaSet.name, tlsaSet.foundName)
	}
	// sort, or leave as-is showing round-robin results order?
	for i := range tlsaSet.RRs {
		name, ok := KnownCAs.NameForTLSA(tlsaSet.RRs[i])
		if ok {
			tlsaLines[i+1] = TLSAMediumString(tlsaSet.RRs[i]) + " ; " + name
		} else {
			tlsaLines[i+1] = TLSAMediumString(tlsaSet.RRs[i])
		}
	}
	status.Waffle(strings.Join(tlsaLines, "\n  "))

	var altNames []string = nil
	if len(otherValidNames) > 0 || len(opts.akaNames) > 0 {
		altNames = make([]string, 0, len(otherValidNames)+len(opts.akaNames))
		altNames = append(altNames, otherValidNames...)
		altNames = append(altNames, opts.akaNames...)
	}

	for _, ip := range ipList {
		if opts.onlyIPv4 && ip.To4() == nil {
			continue
		}
		if opts.onlyIPv6 && ip.To4() != nil {
			continue
		}
		(&validationContext{
			tlsaSet:  tlsaSet,
			hostname: originalHostname,
			altNames: altNames,
			ip:       ip,
			port:     port,
			status:   status,
			time:     time.Now(),
		}).probeAddrGo()
	}
}

func (vc *validationContext) probeAddrGo() {
	vc.status.probing.Add(1)
	vc.status = vc.status.ChildBatcher("probeAddr", vc.ip.String())
	go vc.probeAddr()
}

func (vc *validationContext) probeAddr() {
	// Unfortunately we can't create the ChildBatcher here where it makes most
	// sense, because it needs to be created before the parent calls
	// BatchFinished and closes things on us because of a lack of children.
	defer vc.status.BatchFinished()

	// DialTCP takes the vc.ip/vc.port sensibly, but the moment we want timeout
	// control, we need to go through a function which wants us to join them
	// back into a string first (and so risks the library using DNS).
	//
	// If we think there's a serious risk of that, when given input which looks
	// like IPs, we can now provide a Resolver which fails for hostnames.
	// Alternatively, we could use our own timeout logic, but doing that cleanly
	// requires providing the cancel channel, which is now a deprecated interface.
	// So we can do things "simple but deprecated" or "jumping through many hoops"
	// because the sane way is being hidden away behind too much abstraction.
	raddr := net.JoinHostPort(vc.ip.String(), strconv.Itoa(vc.port))

	conn, err := net.DialTimeout("tcp", raddr, opts.connectTimeout)
	if err != nil {
		vc.status.Errorf("dial failed: %s", err)
		return
	}

	// split out into a separate function which can be invoked by testing
	// utilities on a pre-established connection.
	vc.probeConnectedAddr(conn)
}

func (vc *validationContext) probeConnectedAddr(conn net.Conn) {
	verifier, chCertDetails := peerCertificateVerifierFor(vc)
	tlsConfig := &tls.Config{
		ServerName:            vc.hostname,
		InsecureSkipVerify:    true, // we verify ourselves in the VerifyPeerCertificate
		VerifyPeerCertificate: verifier,
	}

	if opts.tlsOnConnect {
		vc.tryTLSOnConn(conn, tlsConfig, chCertDetails)
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

	vc.Wafflef("issuing STARTTLS [port %d]", vc.port)
	err = s.StartTLS(tlsConfig)
	if err != nil {
		vc.Errorf("STARTTLS failed: %s", err)
	}
	if tlsState, ok := s.TLSConnectionState(); ok {
		vc.checkCertInfo(tlsState, chCertDetails)
	}
	err = s.Quit()
	if err != nil {
		vc.Errorf("QUIT failed: %s", err)
	}
}

func (vc *validationContext) tryTLSOnConn(conn net.Conn, tlsConfig *tls.Config, chCertDetails <-chan certDetails) {
	vc.Messagef("starting TLS immediately [port %d]", vc.port)
	c := tls.Client(conn, tlsConfig)
	t := textproto.NewConn(c)

	_, _, err := t.ReadResponse(220)
	if err != nil {
		t.Close()
		vc.Errorf("banner read failed: %s", err)
		return
	}

	vc.checkCertInfo(c.ConnectionState(), chCertDetails)

	id, err := t.Cmd("EHLO %s", vc.hostname)
	if err == nil {
		t.StartResponse(id)
		_, _, err = t.ReadResponse(250)
		t.EndResponse(id)
	}
	if err != nil {
		vc.Errorf("EHLO failed: %v", err)
		// We don't error here because the server might only support HELO and
		// we still want to QUIT.
	}

	id, err = t.Cmd("QUIT")
	if err == nil {
		t.StartResponse(id)
		_, _, err = t.ReadResponse(221)
		t.EndResponse(id)
	}
	if err != nil {
		vc.Errorf("QUIT failed: %v", err)
	}

	// When speaking to OpenSSL servers, we shut down cleanly without grabbing
	// the EOF first, but when speaking to Golang TLS, that fails us.
	// We don't care if this fails.
	_, _ = t.ReadLine()

	t.Close()
}

func (vc *validationContext) checkCertInfo(cs tls.ConnectionState, chCertDetails <-chan certDetails) {
	if !opts.showCertInfo && !opts.expectOCSP {
		return
	}
	haveOCSP := cs.OCSPResponse != nil && len(cs.OCSPResponse) > 0

	if opts.showCertInfo {
		vc.Messagef("TLS session: version=%v ciphersuite=%v ocsp=%v", tlsVersionString(cs.Version), tls.CipherSuiteName(cs.CipherSuite), haveOCSP)
	}

	if !haveOCSP {
		if opts.expectOCSP {
			vc.Errorf("missing OCSP response")
		}
		return
	}
	count := 0
	for cd := range chCertDetails {
		count += 1
		if cd.validChain == nil || len(cd.validChain) < 1 {
			vc.Messagef("  OCSP: not validating for chainless %s", strconv.QuoteToGraphic(cd.eeCert.Subject.CommonName))
			continue
		}
		liveStaple, err := ocsp.ParseResponseForCert(cs.OCSPResponse, cd.eeCert, cd.validChain[0])
		if err != nil {
			// We can try a coercion of err.(ocsp.ResponseError) and inspect,
			// but while ocsp.TryLater is interesting for a response from an
			// OCSP issuing service, in a staple served by a live TLS service,
			// it's still an error.
			// There's no error here which we want to treat "differently".
			vc.Errorf("  OCSP: response invalid for %s from %s:\n        %s",
				cd.eeCert.Subject.CommonName,
				cd.validChain[0].Subject.CommonName,
				err)
			continue
		}

		switch liveStaple.Status {
		case ocsp.Good:
			tmpl := "OCSP: GOOD status=%v sn=%v producedAt=(%s) thisUpdate=(%s) nextUpdate=(%s)"
			if opts.showCertInfo {
				tmpl = "  " + tmpl
			}
			if opts.expectOCSP {
				tmpl = ColorGreen(tmpl)
			}
			vc.Messagef(tmpl,
				liveStaple.Status, liveStaple.SerialNumber,
				liveStaple.ProducedAt, liveStaple.ThisUpdate, liveStaple.NextUpdate)
		case ocsp.Revoked:
			vc.Errorf("  OCSP: REVOKED status=%v RevokedAt=(%s)", liveStaple.Status, liveStaple.RevokedAt)
		default:
			vc.Errorf("  OCSP: BAD status=%v sn=%v", liveStaple.Status, liveStaple.SerialNumber)
		}
	}
	if count == 0 {
		vc.Errorf("Saw OCSP response but got no chain information out of validation")
	}
}

func tlsVersionString(raw uint16) string {
	// We handle more than just TCP or current versions, because the cost is
	// low and seeing an unexpected version should at least report a known
	// label so people can blink without having to use a search engine to look
	// up 16-bit hex values.
	switch raw {
	// Start with Golang stdlib non-deprecated constants
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"

	// For the rest, the return value string is our code documentation.
	case 0x0300:
		return "SSL3.0"
	case 0x0002:
		return "SSL2.0"
	case 0xFEFF:
		return "DTLS1.0"
	case 0xFEFD:
		return "DTLS1.2"

	default:
		return fmt.Sprintf("%#04x", raw)
	}
}
