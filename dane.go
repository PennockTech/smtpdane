// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

//go:build go1.8

package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type certDetails struct {
	eeCert     *x509.Certificate
	validChain []*x509.Certificate
}

func peerCertificateVerifierFor(vc *validationContext) (
	func([][]byte, [][]*x509.Certificate) error,
	<-chan certDetails,
) {
	// This has the potential to deadlock, because we write to the channel while
	// verifying TLS but don't read from it until after TLS is established, and
	// while we could set up an extra go-routine to avoid that, in practice I
	// think we'll be fine for now just making it sufficiently buffered.
	// There's usually one or two chains total, and we only write _verified_ chain details.
	// 64 won't protect us against abusive servers, but should be sane for everything else.
	// FIXME: consider absorbing results in a separate go-routine spun up
	// before TLS to be proof against even the most abusive servers too.
	ch := make(chan certDetails, 64)

	f := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		return peerCertificateVerifier(vc, ch, rawCerts, verifiedChains)
	}

	return f, ch
}

// A curried version of this is put in the tls.Config.VerifyPeerCertificate field (Go 1.8+)
// and is responsible for TLS verification, replacing the normal PKIX logic.
func peerCertificateVerifier(
	vc *validationContext, chCertDetails chan<- certDetails,
	rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	// because tls.Config set InsecureSkipVerify the verifiedChains field will be nil
	defer close(chCertDetails)

	// rawCerts to certs logic ripped straight from crypto/tls
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, asn1Data := range rawCerts {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return errors.New("danetls: failed to parse certificate from server: " + err.Error())
		}
		certs[i] = cert
	}

	if len(certs) == 0 {
		return errors.New("danetls: no certificates seen from server")
	}

	eeCert := certs[0]
	caCerts := certs[1:]

	// we want to report _all_ matches, for diagnostics
	seenMatch := false

	for _, tlsa := range vc.tlsaSet.RRs {
		switch tlsa.Usage {

		case 3: // DANE-EE per RFC7218
			err := tlsa.Verify(eeCert)
			if err == nil {
				vc.Successf("TLSA DANE-EE(3) match: %s", TLSAShortString(tlsa))
				vc.showCertChainInfo(eeCert)
				seenMatch = true
				chCertDetails <- certDetails{eeCert: eeCert}
			}

		case 2: // DANE-TA per RFC7218
			for i, cert := range caCerts {
				err := tlsa.Verify(cert)
				if err == nil {
					if vc.chainValid(eeCert, cert, caCerts, i) {
						vc.Successf("TLSA DANE-TA(2) match against chain position %d: %s", i+2, TLSAShortString(tlsa))
						vc.showCertChainInfo(eeCert, caCerts[:i+1]...)
						seenMatch = true
						chCertDetails <- certDetails{eeCert: eeCert, validChain: caCerts[:i+1]}
						// if a self-signed cert appears multiple times, report that; don't abort
					} else {
						vc.Errorf("TLSA DANE(2) match against UNCHAINED cert, position %d: %s", i+2, TLSAShortString(tlsa))
					}
				}
			}

		}
	}

	if seenMatch {
		return nil
	}
	return errors.New("danetls: no trust anchors matched certificate chain")
}

func (vc *validationContext) chainValid(eeCert, anchorCert *x509.Certificate, caCerts []*x509.Certificate, caIndex int) bool {
	vOpts := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		CurrentTime:   vc.time,
		Intermediates: x509.NewCertPool(),
	}

	for _, cert := range caCerts[:caIndex] {
		vOpts.Intermediates.AddCert(cert)
	}
	vOpts.Roots.AddCert(anchorCert)

	candidateNames := make([]string, 1+len(vc.altNames))
	candidateNames[0] = vc.hostname
	for i := range vc.altNames {
		candidateNames[i+1] = vc.altNames[i]
	}

	returnStatus := false

	for _, tryHostname := range candidateNames {
		vOpts.DNSName = tryHostname
		chains, err := eeCert.Verify(vOpts)
		if err != nil {
			vc.Wafflef("no valid TA chains for hostname %q [%v]", tryHostname, err)
			continue
		}
		// On some non-Unix platforms, the system verifier can be called, and there's a mode where that returns nil,nil
		if chains == nil {
			vc.Wafflef("when asking for TA chains for hostname %q we got a nil response without error", tryHostname)
			continue
		}

		ids := make([]string, len(chains[0]))
		for i := range chains[0] {
			ids[i] = strconv.QuoteToGraphic(chains[0][i].Subject.CommonName)
		}
		vc.Wafflef("hostname %q has %d chains to TA; first length %d, is: %v", tryHostname, len(chains), len(chains[0]), ids)
		returnStatus = true
	}

	if opts.terse && !returnStatus {
		// terse suppresses the waffle messages, still want _something_
		vc.Messagef("no valid TA chains for %d hostnames: %v", len(candidateNames), candidateNames)
	}

	return returnStatus
}

func (vc *validationContext) showCertChainInfo(cert1 *x509.Certificate, certs ...*x509.Certificate) {
	certPtrList := make([]*x509.Certificate, 1, 1+len(certs))
	certPtrList[0] = cert1
	certPtrList = append(certPtrList, certs...)

	if opts.expirationWarning != 0 {
		now := time.Now()
		minReqTime := now.Add(opts.expirationWarning)
		for i, c := range certPtrList {
			if c.NotAfter.Before(now) {
				vc.Errorf("Cert %d EXPIRED: after %v for cert %s",
					i, c.NotAfter, strconv.QuoteToGraphic(c.Subject.CommonName))
			} else if c.NotAfter.Before(minReqTime) {
				vc.Warnf("Cert %d EXPIRING SOON: within %v of %v for cert %s",
					i, opts.expirationWarning, c.NotAfter, strconv.QuoteToGraphic(c.Subject.CommonName))
			}
		}
	}

	if opts.showCerts {
		pemData := make([]byte, 0, 100*70*len(certPtrList))
		for ci, c := range certPtrList {
			pemData = append(pemData, []byte(fmt.Sprintf("# [%d] CN=%s\n", ci+1, strconv.QuoteToGraphic(c.Subject.CommonName)))...)
			pemData = append(pemData, pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: c.Raw,
			})...)
		}
		vc.Messagef("Certificate PEM chain of %d certs:\n%s", len(certPtrList), pemData)
	}

	if !opts.showCertInfo {
		return
	}

	// certPtrList[ci].PublicKeyAlgorithm has no .String(), alas

	const LinesPerCert = 5
	lines := make([]string, len(certPtrList)*LinesPerCert)
	for ci, c := range certPtrList {
		lines[ci*LinesPerCert+0] = fmt.Sprintf("  [%d] CN=%s", ci+1, strconv.QuoteToGraphic(c.Subject.CommonName))
		lines[ci*LinesPerCert+1] = fmt.Sprintf("\tDN: %s", strconv.QuoteToGraphic(c.Subject.String()))
		lines[ci*LinesPerCert+2] = fmt.Sprintf("\tSAN: %v %v", c.DNSNames, c.IPAddresses)
		lines[ci*LinesPerCert+3] = fmt.Sprintf("\tValid: %v - %v", c.NotBefore, c.NotAfter)
		lines[ci*LinesPerCert+4] = fmt.Sprintf("\tSerial=%v SignedWith: %v", c.SerialNumber, c.SignatureAlgorithm)
	}

	vc.Messagef("Certificate chain of %d certs:\n%s", len(certPtrList), strings.Join(lines, "\n"))
}
