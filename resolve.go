// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"

	"go.pennock.tech/smtpdane/internal/errorlist"

	"github.com/miekg/dns"
)

const EnvKeyDNSResolver = "DNS_RESOLVER"

var dnsSettings struct {
	sync.RWMutex
	conf   *dns.ClientConfig
	client *dns.Client
}

func initDNS() (*dns.ClientConfig, *dns.Client, error) {
	dnsSettings.RLock()
	if dnsSettings.client != nil {
		defer dnsSettings.RUnlock()
		return dnsSettings.conf, dnsSettings.client, nil
	}
	dnsSettings.RUnlock()
	dnsSettings.Lock()
	defer dnsSettings.Unlock()
	if dnsSettings.client != nil {
		return dnsSettings.conf, dnsSettings.client, nil
	}

	var (
		conf *dns.ClientConfig
		err  error
	)
	if os.Getenv(EnvKeyDNSResolver) == "" {
		conf, err = dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, nil, err
		}
	}

	c := new(dns.Client)

	dnsSettings.conf = conf
	dnsSettings.client = c

	return dnsSettings.conf, dnsSettings.client, nil
}

// FIXME: THIS IS NOT DOING WHAT THE NAME SAYS YET!!
// This just resolves DNS, does not validate it.  We're still doing code scaffolding.
// nb: we _do_ check for AD bit set, so we're working with a validating
// resolver fine, but I want to get this working without needing a validating resolver.
// This should be a standalone monitoring tool.
func resolveSecure(hostname string) ([]net.IP, error) {
	config, c, err := initDNS()
	if err != nil {
		return nil, err
	}

	resolver := os.Getenv(EnvKeyDNSResolver)
	if resolver == "" {
		resolver = config.Servers[0] + ":" + config.Port
	} else {
		resolver += ":53"
	}

	addrList := make([]net.IP, 0, 20)
	errList := errorlist.New()

	m := new(dns.Msg)
	m.SetEdns0(dns.DefaultMsgSize, true)

	// why is this uint16 ipv dns.Type ?  Infelicity stuck in API?
	//DNS_RRTYPE_LOOP:
	for _, typ := range []uint16{dns.TypeAAAA, dns.TypeA} {
		// We will qualify if needed; if someone invokes with "foo" as a hostname,
		// look it up and expect the original "foo" in the certificate.
		m.SetQuestion(dns.Fqdn(hostname), typ)

		// TODO: iterate DNS servers, add retries
		r, _, err := c.Exchange(m, resolver)
		if err != nil {
			errList.Add(err)
			continue
		}
		if r.Rcode != dns.RcodeSuccess {
			errList.Add(fmt.Errorf("DNS lookup non-successful: %v", r.Rcode))
			continue
		}
		// Here we depend upon AD bit and so are still secure, assuming secure
		// link to trusted resolver.
		if !r.AuthenticatedData {
			errList.Add(fmt.Errorf("not AD set for results for %q/%v query", hostname, dns.Type(typ)))
			continue
		}

	DNS_ANSWER_RR_LOOP:
		for _, rr := range r.Answer {
			// TODO: CNAME?
			if rr.Header().Rrtype != typ {
				continue
			}
			switch typ {
			case dns.TypeA:
				if ip, ok := dns.Copy(rr).(*dns.A); ok {
					addrList = append(addrList, ip.A)
				} else {
					errList.Add(fmt.Errorf("A record failed to cast to *dns.A [%q/%v]", hostname, dns.Type(typ)))
					// If this happens and we iterate DNS_ANSWER_RR_LOOP instead of DNS_RRTYPE_LOOP then we'll probably get a lot
					// of errors because each fails, as it's _likely_ a programming bug rather than a packet well-formedness
					// issue; for now, accept that, let's see what happens if this is ever tickled.
					continue DNS_ANSWER_RR_LOOP
				}
			case dns.TypeAAAA:
				if ip, ok := dns.Copy(rr).(*dns.AAAA); ok {
					addrList = append(addrList, ip.AAAA)
				} else {
					errList.Add(fmt.Errorf("AAAA record failed to cast to *dns.AAAA [%q/%v]", hostname, dns.Type(typ)))
					continue DNS_ANSWER_RR_LOOP
				}
			}
		}
	}

	if len(addrList) == 0 {
		errList.Add(errors.New("no IP addresses found"))
		return nil, errList
	}
	return addrList, errList.Maybe()
}

type TLSAset struct {
	RRs       []*dns.TLSA
	name      string
	foundName string
}

func resolveTLSA(hostname string, port int) (*TLSAset, error) {
	config, c, err := initDNS()
	if err != nil {
		return nil, err
	}

	resolver := os.Getenv(EnvKeyDNSResolver)
	if resolver == "" {
		resolver = config.Servers[0] + ":" + config.Port
	} else {
		resolver += ":53"
	}

	TLSAList := make([]*dns.TLSA, 0, 20)

	m := new(dns.Msg)
	m.SetEdns0(dns.DefaultMsgSize, true)

	tlsaName := fmt.Sprintf("_%d._tcp.%s", port, dns.Fqdn(hostname))
	m.SetQuestion(tlsaName, dns.TypeTLSA)

	r, _, err := c.Exchange(m, resolver)
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS lookup non-successful: %v", r.Rcode)
	}
	if !r.AuthenticatedData {
		return nil, fmt.Errorf("not AD set for results for %q/%v query", hostname, dns.Type(dns.TypeTLSA))
	}

	for _, rr := range r.Answer {
		if rr.Header().Rrtype != dns.TypeTLSA {
			continue
		}
		if tlsa, ok := dns.Copy(rr).(*dns.TLSA); ok {
			TLSAList = append(TLSAList, tlsa)
		} else {
			return nil, errors.New("TLSA record failed to cast to *dns.TLSA")
		}
	}

	if len(TLSAList) == 0 {
		return nil, errors.New("no TLSA records found")
	}
	return &TLSAset{
		RRs:       TLSAList,
		name:      tlsaName,
		foundName: TLSAList[0].Hdr.Name,
	}, nil
}

// TLSAShortString provides something suitable for output without showing the
// full contents; for our uses, we don't need the RR_Header and for
// full-certs-in-DNS we don't _want_ to print it all.
func TLSAShortString(rr *dns.TLSA) string {
	return strconv.Itoa(int(rr.Usage)) +
		" " + strconv.Itoa(int(rr.Selector)) +
		" " + strconv.Itoa(int(rr.MatchingType)) +
		" " + rr.Certificate[:16] + "..."
}
