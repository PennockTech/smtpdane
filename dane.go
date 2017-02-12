// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

// +build go1.8

package main

import (
	"crypto/x509"
	"errors"
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

	// FIXME: SECURITY: THIS DOESN'T CONFIRM CERTS ARE LINKED IN A CHAIN!
	for _, tlsa := range vc.tlsaSet.RRs {
		switch tlsa.Usage {
		case 3: // DANE-EE per RFC7218
			err := tlsa.Verify(eeCert)
			if err == nil {
				vc.Messagef("TLSA DANE-EE(3) match: %s", tlsa)
				seenMatch = true
			}
		case 2: // DANE-TA per RFC7218
			for i, cert := range caCerts {
				err := tlsa.Verify(cert)
				if err == nil {
					vc.Messagef("TLSA DANE-TA(2) match against parent %d: %s", i, tlsa)
					seenMatch = true
					// if a self-signed cert appears multiple times, report that.
				}
			}
		}
	}

	if seenMatch {
		return nil
	}
	return errors.New("danetls: no trust anchors matched certificate chain")
}
