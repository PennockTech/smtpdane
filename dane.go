// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

// +build go1.8

package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func peerCertificateVerifierFor(vc validationContext) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		return peerCertificateVerifier(vc, rawCerts, verifiedChains)
	}
}

// A curried version of this is put in the tls.Config.VerifyPeerCertificate field (Go 1.8+)
// and is responsible for TLS verification, replacing the normal PKIX logic.
func peerCertificateVerifier(
	vc validationContext,
	rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	// because tls.Config set InsecureSkipVerify the verifiedChains field will be nil

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
			}

		case 2: // DANE-TA per RFC7218
			for i, cert := range caCerts {
				err := tlsa.Verify(cert)
				if err == nil {
					if vc.chainValid(eeCert, cert, caCerts, i) {
						vc.Successf("TLSA DANE-TA(2) match against chain position %d: %s", i+2, TLSAShortString(tlsa))
						vc.showCertChainInfo(eeCert, caCerts[:i+1]...)
						seenMatch = true
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

func (vc validationContext) chainValid(eeCert, anchorCert *x509.Certificate, caCerts []*x509.Certificate, caIndex int) bool {
	opts := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		CurrentTime:   vc.time,
		Intermediates: x509.NewCertPool(),
	}

	for _, cert := range caCerts[:caIndex] {
		opts.Intermediates.AddCert(cert)
	}
	opts.Roots.AddCert(anchorCert)

	candidateNames := make([]string, 1+len(vc.altNames))
	candidateNames[0] = vc.hostname
	for i := range vc.altNames {
		candidateNames[i+1] = vc.altNames[i]
	}

	returnStatus := false

	for _, tryHostname := range candidateNames {
		opts.DNSName = tryHostname
		chains, err := eeCert.Verify(opts)
		if err != nil {
			vc.Messagef("no valid TA chains for hostname %q", tryHostname)
			continue
		}

		ids := make([]string, len(chains[0]))
		for i := range chains[0] {
			ids[i] = strconv.QuoteToGraphic(chains[0][i].Subject.CommonName)
		}
		vc.Messagef("%d chains to TA; first length %d, is: %v", len(chains), len(chains[0]), ids)
		returnStatus = true
	}

	return returnStatus
}

func (vc validationContext) showCertChainInfo(cert1 *x509.Certificate, certs ...*x509.Certificate) {
	certPtrList := make([]*x509.Certificate, 1, 1+len(certs))
	certPtrList[0] = cert1
	certPtrList = append(certPtrList, certs...)

	// FIXME: expiration warning goes here

	if !opts.showCertInfo {
		return
	}

	// certPtrList[ci].PublicKeyAlgorithm has no .String(), alas

	const LinesPerCert = 4
	lines := make([]string, len(certPtrList)*LinesPerCert)
	for ci := range certPtrList {
		lines[ci*LinesPerCert+0] = fmt.Sprintf("  [%d] CN=%s",
			ci+1, strconv.QuoteToGraphic(certPtrList[ci].Subject.CommonName))
		lines[ci*LinesPerCert+1] = fmt.Sprintf("\tSAN: %v %v",
			certPtrList[ci].DNSNames, certPtrList[ci].IPAddresses)
		lines[ci*LinesPerCert+2] = fmt.Sprintf("\tValid: %v - %v",
			certPtrList[ci].NotBefore, certPtrList[ci].NotAfter)
		lines[ci*LinesPerCert+3] = fmt.Sprintf("\tSerial=%v SignedWith: %v",
			certPtrList[ci].SerialNumber, certPtrList[ci].SignatureAlgorithm)
	}

	vc.Messagef("Certificate chain of %d certs:\n%s", len(certPtrList), strings.Join(lines, "\n"))
}
