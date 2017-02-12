// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

// +build go1.8

package main

import (
	"crypto/x509"
	"errors"
)

func peerCertificateVerifierFor(tlsaSet *TLSAset) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		return peerCertificateVerifier(tlsaSet, rawCerts, verifiedChains)
	}
}

// A curried version of this is put in the tls.Config.VerifyPeerCertificate field (Go 1.8+)
// and is responsible for TLS verification, replacing the normal PKIX logic.
func peerCertificateVerifier(tlsaSet *TLSAset, rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	// because tls.Config set InsecureSkipVerify the verifiedChains field will be nil

	// much of this logic ripped straight from crypto/tls

	certs := make([]*x509.Certificate, len(rawCerts))
	for i, asn1Data := range rawCerts {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return errors.New("tls: failed to parse certificate from server: " + err.Error())
		}
		certs[i] = cert
	}

	// FIXME: IMPLEMENT

	return nil
}
