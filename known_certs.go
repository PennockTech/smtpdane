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
	"io/ioutil"
	"os"

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
	if len(cert.Subject.CommonName) > 0 {
		label = cert.Subject.CommonName
	} else if len(cert.DNSNames) > 0 {
		label = cert.DNSNames[0]
	} else if len(cert.Subject.Country) > 0 && len(cert.Subject.Organization) > 0 {
		label = cert.Subject.Country[0] + " " + cert.Subject.Organization[0]
		if len(cert.Subject.OrganizationalUnit) > 0 {
			label += " " + cert.Subject.OrganizationalUnit[0]
		}
	} else {
		// fmt.Printf("unable to get name for cert: %#v\n", cert.Subject)
		return
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
	)
	// empty or invalid env-vars inhibit system loading; deliberate
	if fn, ok := os.LookupEnv(envKeySSLfile); ok {
		fileList = []string{fn}
	}
	if dn, ok := os.LookupEnv(envKeySSLdir); ok {
		dirList = []string{dn}
	}

	for _, fn := range fileList {
		data, err := ioutil.ReadFile(fn)
		if err == nil {
			ok := known.AddFromPEM(data)
			if ok {
				return
			}
		}
	}

	for _, directory := range dirList {
		fis, err := ioutil.ReadDir(directory)
		if err != nil {
			continue
		}
		rootsAdded := false
		for _, fi := range fis {
			data, err := ioutil.ReadFile(directory + "/" + fi.Name())
			if err == nil && known.AddFromPEM(data) {
				rootsAdded = true
			}
		}
		if rootsAdded {
			return
		}
	}

	return nil
}

func init() { KnownCAs = loadKnownCAs() }
