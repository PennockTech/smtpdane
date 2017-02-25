// Copyright © 2017 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
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

func resolversFromList(input []string, defDNSPort string) []string {
	r := make([]string, len(input))
	for i := range input {
		r[i] = HostPortWithDefaultPort(input[i], defDNSPort)
	}
	return r
}

var resolverSplitRE *regexp.Regexp

func init() {
	resolverSplitRE = regexp.MustCompile(`[,\s]+`)
}

func resolversFromString(input string) []string {
	return resolversFromList(resolverSplitRE.Split(input, -1), "53")
}

// FIXME: This is not doing DNS validation locally.
// It's resolving DNS, delegating trust in validation to the resolver by
// trusting the AD bit.
// I want to get this working without needing a validating resolver.
// This should be a standalone monitoring tool.
func resolveRRSecure(
	// the cbfunc is called the the confirmed RR type and the rr and the rrname;
	// it should return an item to be added to the resolveRRSecure return list,
	// and an error; non-nil error inhibits appending to the list.
	cbfunc func(typ uint16, rr dns.RR, rrname string) (interface{}, error),
	rrname string,
	typlist ...uint16,
) ([]interface{}, error) {
	config, c, err := initDNS()
	if err != nil {
		return nil, err
	}

	var resolvers []string
	if r := os.Getenv(EnvKeyDNSResolver); r != "" {
		resolvers = resolversFromString(r)
	} else {
		resolvers = resolversFromList(config.Servers, config.Port)
	}

	resultList := make([]interface{}, 0, 20)
	errList := errorlist.New()

	m := new(dns.Msg)
	m.SetEdns0(dns.DefaultMsgSize, true)

	// why is this uint16 ipv dns.Type ?  Infelicity stuck in API?
DNS_RRTYPE_LOOP:
	for _, typ := range typlist {
		m.SetQuestion(rrname, typ)

		var (
			r   *dns.Msg
			err error
		)

		for _, resolver := range resolvers {
			// TODO: add retries
			r, _, err = c.Exchange(m, resolver)
			if err != nil {
				errList.Add(err)
				r = nil
				continue
			}
			if r.Rcode != dns.RcodeSuccess {
				failure, known := dns.RcodeToString[r.Rcode]
				if !known {
					failure = fmt.Sprintf("Rcode<%d> (unknown)", r.Rcode)
				}
				errList.AddErrorf("DNS lookup non-successful [resolver %v]: %v", resolver, failure)
				r = nil
				continue
			}
			// Here we depend upon AD bit and so are still secure, assuming secure
			// link to trusted resolver.
			if !r.AuthenticatedData {
				errList.AddErrorf("not AD set for results from %v for %q/%v query", resolver, rrname, dns.Type(typ))
				r = nil
				continue
			}
		}

		if r == nil {
			errList.AddErrorf("[%q/%v]: all DNS resolver queries failed, unable to get authentic result", rrname, dns.Type(typ))
			// seems likely might be SERVFAIL from broken auth servers for AAAA records
			continue DNS_RRTYPE_LOOP
		}

		for _, rr := range r.Answer {
			// TODO: CNAME?
			if rr.Header().Rrtype != typ {
				continue
			}
			x, err := cbfunc(typ, dns.Copy(rr), rrname)
			if err != nil {
				errList.Add(err)
			} else {
				resultList = append(resultList, x)
			}
		}
	}

	if len(resultList) == 0 {
		errList.Add(errors.New("no results found"))
		return nil, errList
	}
	return resultList, errList.Maybe()
}

// There's a lot of repetition/boilerplate in the below.
// If we expand beyond where we are at now, then we really should consider reflection; more complexity, less repetition.

func cbRRTypeAddr(typ uint16, rr dns.RR, rrname string) (interface{}, error) {
	switch typ {
	case dns.TypeA:
		if ip, ok := rr.(*dns.A); ok {
			return ip.A, nil
		} else {
			return nil, fmt.Errorf("A record failed to cast to *dns.A [%q/%v]", rrname, dns.Type(typ))
		}
	case dns.TypeAAAA:
		if ip, ok := rr.(*dns.AAAA); ok {
			return ip.AAAA, nil
		} else {
			return nil, fmt.Errorf("AAAA record failed to cast to *dns.AAAA [%q/%v]", rrname, dns.Type(typ))
		}
	}
	return nil, fmt.Errorf("BUG: cbRRTypeAddr(%v,..,%q) called, expected A/AAAA", dns.Type(typ), rrname)
}

func ResolveAddrSecure(hostname string) ([]net.IP, error) {
	rl, e := resolveRRSecure(cbRRTypeAddr, dns.Fqdn(hostname), dns.TypeAAAA, dns.TypeA)
	if e != nil {
		return nil, e
	}
	addrList := make([]net.IP, len(rl))
	for i := range rl {
		addrList[i] = rl[i].(net.IP)
	}
	return addrList, nil
}

type TLSAset struct {
	RRs       []*dns.TLSA
	name      string
	foundName string
}

func cbRRTypeTLSA(typ uint16, rr dns.RR, rrname string) (interface{}, error) {
	switch typ {
	case dns.TypeTLSA:
		if tlsa, ok := rr.(*dns.TLSA); ok {
			return tlsa, nil
		} else {
			return nil, fmt.Errorf("TLSA record failed to cast to *dns.TLSA [%q/%v]", rrname, dns.Type(typ))
		}
	}
	return nil, fmt.Errorf("BUG: cbRRTypeTLSA(%v,..,%q) called, expected TLSA", dns.Type(typ), rrname)
}

func ResolveTLSA(hostname string, port int) (*TLSAset, error) {
	tlsaName := fmt.Sprintf("_%d._tcp.%s", port, dns.Fqdn(hostname))
	rl, e := resolveRRSecure(cbRRTypeTLSA, tlsaName, dns.TypeTLSA)
	if e != nil {
		return nil, e
	}

	TLSAList := make([]*dns.TLSA, len(rl))
	for i := range rl {
		TLSAList[i] = rl[i].(*dns.TLSA)
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

func cbRRTypeMX(typ uint16, rr dns.RR, rrname string) (interface{}, error) {
	switch typ {
	case dns.TypeMX:
		if mx, ok := rr.(*dns.MX); ok {
			return mx.Mx, nil
		} else {
			return nil, fmt.Errorf("MX record failed to cast to *dns.MX [%q/%v]", rrname, dns.Type(typ))
		}
	}
	return nil, fmt.Errorf("BUG: cbRRTypeMX(%v,..,%q) called, expected MX", dns.Type(typ), rrname)
}

// ResolveMX only returns the hostnames, we don't care about the Preference
func ResolveMX(hostname string) ([]string, error) {
	rl, e := resolveRRSecure(cbRRTypeMX, dns.Fqdn(hostname), dns.TypeMX)
	if e != nil {
		return nil, e
	}
	hostnameList := make([]string, len(rl))
	for i := range rl {
		hostnameList[i] = rl[i].(string)
	}
	return hostnameList, nil
}

func cbRRTypeSRV(typ uint16, rr dns.RR, rrname string) (interface{}, error) {
	switch typ {
	case dns.TypeSRV:
		if srv, ok := rr.(*dns.SRV); ok {
			return srv, nil
		} else {
			return nil, fmt.Errorf("SRV record failed to cast to *dns.SRV [%q/%v]", rrname, dns.Type(typ))
		}
	}
	return nil, fmt.Errorf("BUG: cbRRTypeSRV(%v,..,%q) called, expected SRV", dns.Type(typ), rrname)
}

// ResolveSRV returns MX records, we need at least the Port, not just the Target
func ResolveSRV(lookup string) ([]*dns.SRV, error) {
	rl, e := resolveRRSecure(cbRRTypeSRV, lookup, dns.TypeSRV)
	if e != nil {
		return nil, e
	}
	srvList := make([]*dns.SRV, len(rl))
	for i := range rl {
		srvList[i] = rl[i].(*dns.SRV)
	}
	return srvList, nil
}
