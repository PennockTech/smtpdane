// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

// This file tries to load known certs, to get named identities with which
// to label TLSA records; the Golang cert_pool handling doesn't let us look
// at each certificate, and I'm disinclined to replicate the alternative
// trust store handling for stuff like Darwin's Security Framework.
//
// So we go as far as handling the environment variables and some common
// locations, but no further.  For myself, I have the env vars set, even
// on Darwin, so this works for me.
//
// Sane suggestions for improvements are welcome.

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
)

const (
	// match common OpenSSL tooling; crypto/cryptlib.h
	envKeySSLfile = "SSL_CERT_FILE"
	envKeySSLdir  = "SSL_CERT_DIR"
)

var commonCertFileLocations = []string{
	// from crypto/x509:
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
	"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
	"/etc/pki/tls/cacert.pem",                           // OpenELEC
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
	// others
	"/usr/local/etc/ssl/cert.pem",            // FreeBSD ca_root_nss port also
	"/usr/local/share/certs/ca-root-nss.crt", // FreeBSD ca_root_nss
	"/usr/local/openssl/cert.pem",            // FreeBSD openssl port
	"/etc/pki/tls/certs/ca-bundle.trust.crt",
}

var commonCertDirLocations = []string{
	// from crypto/x509
	"/etc/ssl/certs",               // SLES10/SLES11, https://golang.org/issue/12139
	"/system/etc/security/cacerts", // Android
	// other
	"/usr/local/openssl/certs", // FreeBSD openssl port
	"/etc/x509/certs",
	"/var/lib/ca-certificates",
	// /etc/pki/tls/certs appears to be intended for local certs for local services,
	// not as a system trust store, unlike either of the files within listed above.
}

type certInfo struct {
	label string
	cert  *x509.Certificate
}

type certKey string

type knownCAt struct {
	certs map[certKey]certInfo
}

var KnownCAs *knownCAt

// AddFromPEM is a rip from crypto/x509.CertPool.AppendCertsFromPEM()
func (k *knownCAt) AddFromPEM(pemCerts []byte) (ok bool) {
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		k.AddOneCert(cert)
		ok = true
	}

	return
}

func (k *knownCAt) NameForFields(selector, matchingType uint8, caData string) (string, bool) {
	if k == nil || k.certs == nil {
		return "", false
	}
	key := certKey(fmt.Sprintf("%d/%d/%s", selector, matchingType, caData))
	ci, ok := k.certs[key]
	if ok {
		return ci.label, ok
	}
	return "", false
}

func (k *knownCAt) NameForTLSA(t *dns.TLSA) (string, bool) {
	return k.NameForFields(t.Selector, t.MatchingType, t.Certificate)
}

func (k *knownCAt) AddOneCert(cert *x509.Certificate) {
	var label string
	const MIN_SENSIBLE_LEN = 5
	// This logic pre-dates Golang stdlib gaining .String() on the DN
	// I _like_ the conciseness though, so I'm trying to make it last a little longer.
	if len(cert.Subject.CommonName) > 0 {
		label = cert.Subject.CommonName
		if len(label) < MIN_SENSIBLE_LEN && len(cert.Subject.Organization) > 0 {
			// Let's Encrypt at R3/R4/E1/E2 time (2020) switched to minimize the CN and using the O field
			label = strings.Join(cert.Subject.Organization, ", ") + " // " + label
		}
	} else if len(cert.DNSNames) > 0 {
		label = cert.DNSNames[0]
	} else if len(cert.Subject.Country) > 0 && len(cert.Subject.Organization) > 0 {
		label = cert.Subject.Country[0] + " " + cert.Subject.Organization[0]
		if len(cert.Subject.OrganizationalUnit) > 0 {
			label += " " + cert.Subject.OrganizationalUnit[0]
		}
	} else {
		label = cert.Subject.String()
	}
	if len(label) < MIN_SENSIBLE_LEN {
		t := cert.Subject.String()
		if len(t) >= MIN_SENSIBLE_LEN {
			label = t
		}
	}

	for selector := uint8(0); selector <= 1; selector++ {
		for matchingType := uint8(0); matchingType <= 2; matchingType++ {
			caData, err := dns.CertificateToDANE(selector, matchingType, cert)
			if err == nil {
				key := certKey(fmt.Sprintf("%d/%d/%s", selector, matchingType, caData))
				if selector == 0 && matchingType == 0 {
					if _, have := k.certs[key]; have {
						return
					}
				}
				k.certs[key] = certInfo{
					label: label,
					cert:  cert,
				}
			}
		}
	}

}

func loadKnownCAs() (known *knownCAt) {
	known = &knownCAt{
		certs: make(map[certKey]certInfo, 300),
	}

	var (
		fileList = commonCertFileLocations
		dirList  = commonCertDirLocations
		valid    bool
	)
	// empty or invalid env-vars inhibit system loading; that's deliberate.
	// If either is set, then _only_ those from env are tried.
	// If neither is set, the first location found at all, wins.
	// If both are set, then both are loaded.
	fn, okf := os.LookupEnv(envKeySSLfile)
	dn, okd := os.LookupEnv(envKeySSLdir)
	if okf || okd {
		fileList = nil
		dirList = nil
	}
	if okf {
		fileList = []string{fn}
	}
	if okd {
		dirList = []string{dn}
	}

	for _, fn := range fileList {
		data, err := os.ReadFile(fn)
		if err == nil {
			ok := known.AddFromPEM(data)
			if ok {
				if okd {
					// explicitly given SSL_CERT_DIR and, since we're here,
					// also SSL_CERT_FILE (else would've ranged nil fileList).
					// Iff explicitly given both, then load both.
					valid = true
					break
				}
				return
			}
		}
	}

	for _, directory := range dirList {
		entries, err := os.ReadDir(directory)
		if err != nil {
			continue
		}
		rootsAdded := false
		for _, entry := range entries {
			data, err := os.ReadFile(directory + "/" + entry.Name())
			if err == nil && known.AddFromPEM(data) {
				rootsAdded = true
			}
		}
		if rootsAdded {
			return
		}
	}

	if !valid {
		known = nil
	}
	return
}

func initCertNames() { KnownCAs = loadKnownCAs() }
