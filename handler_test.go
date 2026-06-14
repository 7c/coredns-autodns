package autodns

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

func serveDNS(t *testing.T, a *Autodns, ip string, qname string, qtype uint16) *dns.Msg {
	t.Helper()

	rec := newRecorderWithIP(t, ip)
	m := new(dns.Msg)
	name := qname
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	m.Question = []dns.Question{{Name: name, Qtype: qtype, Qclass: dns.ClassINET}}

	_, err := a.ServeDNS(context.Background(), rec, m)
	if err != nil {
		t.Fatalf("ServeDNS error: %v", err)
	}
	return rec.Msg
}

func TestServeDNSLookups(t *testing.T) {
	a, _ := prepareServeDNS(t)

	tests := []test.Case{
		{
			Qname: "host1.example.net.", Qtype: dns.TypeA,
			Answer: []dns.RR{test.A("host1.example.net. 300 IN A 5.5.5.5")},
		},
		{
			Qname: "foo.example.net.", Qtype: dns.TypeTXT,
			Answer: []dns.RR{test.TXT(`foo.example.net. 300 IN TXT "this is a wildcard"`)},
		},
		{
			Qname: "bar.sub.foo.example.net.", Qtype: dns.TypeTXT,
			Answer: []dns.RR{test.TXT(`bar.sub.foo.example.net. 300 IN TXT "this is a wildcard"`)},
		},
		{
			Qname: "subdel.example.net.", Qtype: dns.TypeNS,
			Answer: []dns.RR{
				test.NS("subdel.example.net. 300 IN NS ns1.subdel.example.net."),
				test.NS("subdel.example.net. 300 IN NS ns2.subdel.example.net."),
			},
		},
		{
			Qname: "foo.example.net.", Qtype: dns.TypeMX,
			Answer: []dns.RR{test.MX("foo.example.net. 300 IN MX 10 host1.example.net.")},
			Extra:  []dns.RR{test.A("host1.example.net. 300 IN A 5.5.5.5")},
		},
		{
			Qname: "_ssh._tcp.host1.example.net.", Qtype: dns.TypeSRV,
			Answer: []dns.RR{test.SRV("_ssh._tcp.host1.example.net. 300 IN SRV 10 100 123 tcp.example.com.")},
		},
		{
			Qname: "host2.example.net.", Qtype: dns.TypeCAA,
			Answer: []dns.RR{test.CAA("host2.example.net. 0 IN CAA 0 issue \"letsencrypt.org\"")},
		},
		{
			Qname: "example.net.", Qtype: dns.TypeSOA,
			Answer: []dns.RR{test.SOA("example.net. 300 IN SOA ns1.example.net. hostmaster.example.net. 303 44 55 66 100")},
		},
	}

	for _, tc := range tests {
		t.Run(tc.Qname+":"+dns.TypeToString[tc.Qtype], func(t *testing.T) {
			resp := serveDNS(t, a, "127.0.0.1", tc.Qname, tc.Qtype)
			if resp == nil {
				t.Fatal("nil response")
			}
			if err := test.SortAndCheck(resp, tc); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestServeDNSNXDOMAIN(t *testing.T) {
	a, mr := newTestAutodns(t)
	zoneKey := a.keyPrefix + exampleZone + a.keySuffix
	mr.HSet(zoneKey, "host1", `{"a":[{"ttl":300,"ip":"5.5.5.5"}]}`)
	a.Zones = []string{exampleZone}

	resp := serveDNS(t, a, "127.0.0.1", "nonexistent.example.net.", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", resp.Rcode)
	}
}

func TestServeDNSNotImplemented(t *testing.T) {
	a, _ := prepareServeDNS(t)
	resp := serveDNS(t, a, "127.0.0.1", "host1.example.net.", dns.TypeHINFO)
	if resp.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("rcode = %d, want NOTIMP", resp.Rcode)
	}
}

func TestServeDNSFallthrough(t *testing.T) {
	a, _ := prepareServeDNS(t)
	a.Next = test.NextHandler(dns.RcodeRefused, nil)

	rec := newRecorderWithIP(t, "127.0.0.1")
	m := new(dns.Msg)
	m.SetQuestion("other.com.", dns.TypeA)

	rcode, err := a.ServeDNS(context.Background(), rec, m)
	if err != nil {
		t.Fatalf("ServeDNS error: %v", err)
	}
	if rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %d, want REFUSED from next handler", rcode)
	}
}

func seedRegistrationZone(t *testing.T, mr *miniredis.Miniredis, a *Autodns) {
	t.Helper()

	zoneKey := a.keyPrefix + exampleZone + a.keySuffix
	mr.HSet(zoneKey, "@", `{"soa":{"ttl":300,"minttl":100,"mbox":"hostmaster.example.net.","ns":"ns1.example.net.","refresh":44,"retry":55,"expire":66},"ns":[{"ttl":300,"host":"ns1.example.net."},{"ttl":300,"host":"ns2.example.net."}]}`)
	a.Zones = []string{exampleZone}
}

func registrationAutodns(t *testing.T) (*Autodns, *miniredis.Miniredis) {
	return registrationAutodnsWithNetworks(t, "100.64.0.0/16")
}

func registrationAutodnsWithNetworks(t *testing.T, cidrs ...string) (*Autodns, *miniredis.Miniredis) {
	t.Helper()

	networks := make([]net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", cidr, err)
		}
		networks = append(networks, *ipNet)
	}

	a, mr := newTestAutodns(t, func(a *Autodns) {
		a.RegisterNetworks = networks
		a.RegisterDeny = readmeRegisterDeny
	})
	seedRegistrationZone(t, mr, a)
	return a, mr
}

func TestServeDNSRegistration(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		a, mr := registrationAutodns(t)
		qname := "_reg.newhost.example.net."
		resp := serveDNS(t, a, "100.64.0.10", qname, dns.TypeTXT)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("rcode = %d, want success", resp.Rcode)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("expected 1 TXT answer, got %d", len(resp.Answer))
		}
		txt, ok := resp.Answer[0].(*dns.TXT)
		if !ok || len(txt.Txt) == 0 || txt.Txt[0] != "newhost.example.net" {
			t.Fatalf("unexpected TXT answer: %v", resp.Answer[0])
		}

		zoneKey := a.keyPrefix + exampleZone + a.keySuffix
		val := mr.HGet(zoneKey, "newhost")
		if !strings.Contains(val, "100.64.0.10") {
			t.Fatalf("redis record = %q, want client IP", val)
		}
	})

	t.Run("denied network", func(t *testing.T) {
		a, _ := registrationAutodns(t)
		resp := serveDNS(t, a, "10.0.0.1", "_reg.newhost.example.net.", dns.TypeTXT)
		if resp.Rcode != dns.RcodeNameError {
			t.Fatalf("rcode = %d, want NXDOMAIN", resp.Rcode)
		}
	})

	t.Run("no register networks", func(t *testing.T) {
		a, mr := newTestAutodns(t)
		seedRegistrationZone(t, mr, a)
		resp := serveDNS(t, a, "100.64.0.10", "_reg.newhost.example.net.", dns.TypeTXT)
		if resp.Rcode != dns.RcodeNameError {
			t.Fatalf("rcode = %d, want NXDOMAIN", resp.Rcode)
		}
	})
}

// TestServeDNSRegisterDeny verifies README register.deny names cannot register via _reg.*.
func TestServeDNSRegisterDeny(t *testing.T) {
	a, mr := registrationAutodns(t)
	zoneKey := a.keyPrefix + exampleZone + a.keySuffix

	for _, label := range readmeRegisterDeny {
		t.Run(label, func(t *testing.T) {
			mr.HDel(zoneKey, label)

			qname := "_reg." + label + ".example.net."
			resp := serveDNS(t, a, "100.64.0.10", qname, dns.TypeTXT)
			if resp.Rcode != dns.RcodeNameError {
				t.Fatalf("_reg.%s: rcode = %d, want NXDOMAIN", label, resp.Rcode)
			}
			if stored := mr.HGet(zoneKey, label); stored != "" {
				t.Fatalf("_reg.%s: must not write redis, got %q", label, stored)
			}
		})
	}

	t.Run("allowed label", func(t *testing.T) {
		const label = "host1"
		mr.HDel(zoneKey, label)

		resp := serveDNS(t, a, "100.64.0.10", "_reg."+label+".example.net.", dns.TypeTXT)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("rcode = %d, want success for allowed label", resp.Rcode)
		}
		if stored := mr.HGet(zoneKey, label); stored == "" {
			t.Fatal("expected redis record for allowed label")
		}
	})
}

func TestServeDNSRegisterNetworkRestrictions(t *testing.T) {
	const qname = "_reg.securehost.example.net."
	const redisField = "securehost"

	a, mr := registrationAutodnsWithNetworks(t, "100.64.0.0/16", "127.0.0.1/32")
	zoneKey := a.keyPrefix + exampleZone + a.keySuffix

	tests := []struct {
		name       string
		clientIP   string
		wantAllow  bool
		wantStored string
	}{
		{name: "tailscale CGNAT range", clientIP: "100.64.0.10", wantAllow: true, wantStored: "100.64.0.10"},
		{name: "loopback allowed", clientIP: "127.0.0.1", wantAllow: true, wantStored: "127.0.0.1"},
		{name: "just outside /16", clientIP: "100.65.0.1", wantAllow: false},
		{name: "loopback neighbor denied", clientIP: "127.0.0.2", wantAllow: false},
		{name: "public internet denied", clientIP: "8.8.8.8", wantAllow: false},
		{name: "RFC1918 denied when not listed", clientIP: "10.0.0.1", wantAllow: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mr.HDel(zoneKey, redisField)

			resp := serveDNS(t, a, tc.clientIP, qname, dns.TypeTXT)
			stored := mr.HGet(zoneKey, redisField)

			if tc.wantAllow {
				if resp.Rcode != dns.RcodeSuccess {
					t.Fatalf("rcode = %d, want success for %s", resp.Rcode, tc.clientIP)
				}
				if !strings.Contains(stored, tc.wantStored) {
					t.Fatalf("redis = %q, want IP %q stored", stored, tc.wantStored)
				}
				return
			}

			if resp.Rcode != dns.RcodeNameError {
				t.Fatalf("rcode = %d, want NXDOMAIN for %s", resp.Rcode, tc.clientIP)
			}
			if stored != "" {
				t.Fatalf("redis should be empty for denied IP %s, got %q", tc.clientIP, stored)
			}
		})
	}
}

func TestServeDNSRegisterNetworkRestrictionsIPv6(t *testing.T) {
	const qname = "_reg.v6host.example.net."
	const redisField = "v6host"

	a, mr := registrationAutodnsWithNetworks(t, "100.64.0.0/16", "fd00::/8")
	zoneKey := a.keyPrefix + exampleZone + a.keySuffix

	tests := []struct {
		name       string
		clientIP   string
		wantAllow  bool
		wantStored string
	}{
		{name: "ULA allowed", clientIP: "fd00::10", wantAllow: true, wantStored: "fd00::10"},
		{name: "global IPv6 denied", clientIP: "2001:db8::1", wantAllow: false},
		{name: "IPv4 still works", clientIP: "100.64.0.10", wantAllow: true, wantStored: "100.64.0.10"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mr.HDel(zoneKey, redisField)

			resp := serveDNS(t, a, tc.clientIP, qname, dns.TypeTXT)
			stored := mr.HGet(zoneKey, redisField)

			if tc.wantAllow {
				if resp.Rcode != dns.RcodeSuccess {
					t.Fatalf("rcode = %d, want success for %s", resp.Rcode, tc.clientIP)
				}
				if !strings.Contains(stored, tc.wantStored) {
					t.Fatalf("redis = %q, want %q", stored, tc.wantStored)
				}
				if strings.Contains(stored, `"aaaa"`) && net.ParseIP(tc.clientIP).To4() == nil {
					if strings.Contains(stored, `"a":`) {
						t.Fatalf("IPv6 client should create AAAA record, got %q", stored)
					}
				}
				return
			}

			if resp.Rcode != dns.RcodeNameError {
				t.Fatalf("rcode = %d, want NXDOMAIN for %s", resp.Rcode, tc.clientIP)
			}
			if stored != "" {
				t.Fatalf("redis should be empty for denied IP %s, got %q", tc.clientIP, stored)
			}
		})
	}
}

func TestServeDNSRegistrationNonTXT(t *testing.T) {
	const qname = "_reg.newhost.example.net."
	const redisField = "newhost"

	a, mr := registrationAutodns(t)
	zoneKey := a.keyPrefix + exampleZone + a.keySuffix

	qtypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeNS, dns.TypeMX}

	for _, qtype := range qtypes {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			mr.HDel(zoneKey, redisField)

			resp := serveDNS(t, a, "100.64.0.10", qname, qtype)
			if resp.Rcode != dns.RcodeNameError {
				t.Fatalf("rcode = %d, want NXDOMAIN for non-TXT _reg query", resp.Rcode)
			}
			if stored := mr.HGet(zoneKey, redisField); stored != "" {
				t.Fatalf("non-TXT _reg query must not write redis, got %q", stored)
			}
		})
	}
}

func TestServeDNSRegistrationIPv6(t *testing.T) {
	a, mr := registrationAutodnsWithNetworks(t, "fd00::/8")
	qname := "_reg.ipv6host.example.net."

	resp := serveDNS(t, a, "fd00::10", qname, dns.TypeTXT)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want success", resp.Rcode)
	}

	zoneKey := a.keyPrefix + exampleZone + a.keySuffix
	stored := mr.HGet(zoneKey, "ipv6host")
	if !strings.Contains(stored, `"aaaa"`) || !strings.Contains(stored, "fd00::10") {
		t.Fatalf("expected AAAA record for IPv6 client, got %q", stored)
	}
	if strings.Contains(stored, `"a":`) {
		t.Fatalf("IPv6 registration must not create A record, got %q", stored)
	}
}
