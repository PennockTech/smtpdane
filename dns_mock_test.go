// Copyright © 2024 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// mockDNSAnswer describes one answer to return for a given query key.
type mockDNSAnswer struct {
	rrs           []dns.RR
	authenticated bool
	rcode         int
	truncated     bool
	slowBy        time.Duration
}

// mockDNSResolver builds a resolver function from a map of answers.
// Map keys are "fqdn/TYPE" e.g. "_25._tcp.mail.example./TLSA" or "mail.example./A".
func mockDNSResolver(answers map[string]mockDNSAnswer) func(*dns.Msg, string) (*dns.Msg, time.Duration, error) {
	return func(m *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
		if len(m.Question) == 0 {
			return nil, 0, fmt.Errorf("mock: empty question")
		}
		q := m.Question[0]
		key := fmt.Sprintf("%s/%s", q.Name, dns.TypeToString[q.Qtype])

		ans, ok := answers[key]
		if !ok {
			// NXDOMAIN for anything unknown
			resp := new(dns.Msg)
			resp.SetReply(m)
			resp.Rcode = dns.RcodeNameError
			return resp, 0, nil
		}

		if ans.slowBy > 0 {
			time.Sleep(ans.slowBy)
		}

		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Rcode = ans.rcode
		resp.AuthenticatedData = ans.authenticated
		resp.Truncated = ans.truncated
		for _, rr := range ans.rrs {
			resp.Answer = append(resp.Answer, dns.Copy(rr))
		}
		return resp, 0, nil
	}
}

// withMockDNS sets testResolverOverride for the duration of fn, then restores it.
func withMockDNS(answers map[string]mockDNSAnswer, fn func()) {
	old := testResolverOverride
	testResolverOverride = mockDNSResolver(answers)
	defer func() { testResolverOverride = old }()
	fn()
}

// mockAnswerKey constructs a mock map key from a hostname and type string.
// hostname should already be fully-qualified (trailing dot).
func mockAnswerKey(hostname, typStr string) string {
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}
	return hostname + "/" + typStr
}

// newMockTLSA creates a TLSA RR for use in mock DNS answers.
func newMockTLSA(name string, usage, selector, matchingType uint8, cert string) *dns.TLSA {
	return &dns.TLSA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeTLSA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Usage:        usage,
		Selector:     selector,
		MatchingType: matchingType,
		Certificate:  cert,
	}
}

// newMockA creates an A RR for use in mock DNS answers.
func newMockA(name, ip string) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP(ip).To4(),
	}
}

// newMockCNAME creates a CNAME RR for use in mock DNS answers.
func newMockCNAME(name, target string) *dns.CNAME {
	return &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Target: dns.Fqdn(target),
	}
}
