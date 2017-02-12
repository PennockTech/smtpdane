// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

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

	m := new(dns.Msg)
	m.SetEdns0(dns.DefaultMsgSize, true)

	// why is this uint16 ipv dns.Type ?  Infelicity stuck in API?
	for _, typ := range []uint16{dns.TypeAAAA, dns.TypeA} {
		// We will qualify if needed; if someone invokes with "foo" as a hostname,
		// look it up and expect the original "foo" in the certificate.
		m.SetQuestion(dns.Fqdn(hostname), typ)

		// TODO: iterate DNS servers, add retries
		r, _, err := c.Exchange(m, resolver)
		if err != nil {
			// TODO: if server fails on AAAA and we have A, we should probably return the A stuff but warn on the failure
			return nil, err
		}
		if r.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("DNS lookup non-successful: %v", r.Rcode)
		}

		// if not authentic, unlikely to be for a second type
		if !r.AuthenticatedData {
			return nil, fmt.Errorf("not AD set for results for %q/%v query", hostname, dns.Type(typ))
		}

		for _, rr := range r.Answer {
			// TODO: CNAME?
			if rr.Header().Rrtype != typ {
				continue
			}
			switch typ {
			case dns.TypeA:
				if ip, ok := rr.(*dns.A); ok {
					addrList = append(addrList, ip.A)
				} else {
					return nil, errors.New("A record failed to cast to *dns.A")
				}
			case dns.TypeAAAA:
				if ip, ok := rr.(*dns.AAAA); ok {
					addrList = append(addrList, ip.AAAA)
				} else {
					return nil, errors.New("AAAA record failed to cast to *dns.AAAA")
				}
			}
		}
	}

	if len(addrList) == 0 {
		return nil, errors.New("no IP addresses found")
	}
	return addrList, nil
}
