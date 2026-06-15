package autodns

import (
	"net"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

const testAcmeDigest = "abc123XYZ-_def456GHI789jkl012MNO345pqr"
const testAcmeDigest2 = "xyz789ABC-_def012GHI345jkl678MNO901pqr234"

func acmeAutodns(t *testing.T) (*Autodns, *miniredis.Miniredis) {
	t.Helper()
	return registrationAutodnsWithNetworks(t, "100.64.0.0/16")
}

func TestParseAcmeRegQuery(t *testing.T) {
	tests := []struct {
		name      string
		qname     string
		wantDigest string
		wantHost  string
		wantOK    bool
	}{
		{name: "apex wildcard", qname: "_acme-reg." + testAcmeDigest + ".example.net.", wantDigest: testAcmeDigest, wantHost: "", wantOK: true},
		{name: "host", qname: "_acme-reg." + testAcmeDigest + ".host1.example.net.", wantDigest: testAcmeDigest, wantHost: "host1", wantOK: true},
		{name: "invalid digest chars", qname: "_acme-reg.bad*digest.host1.example.net.", wantOK: false},
		{name: "wrong prefix", qname: "_reg.host1.example.net.", wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			digest, host, ok := parseAcmeRegQuery(tc.qname, exampleZone)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if digest != tc.wantDigest || host != tc.wantHost {
				t.Fatalf("got (%q, %q), want (%q, %q)", digest, host, tc.wantDigest, tc.wantHost)
			}
		})
	}
}

func TestAcmeRegistrationApex(t *testing.T) {
	a, mr := acmeAutodns(t)
	zoneKey := a.keyPrefix + exampleZone + a.keySuffix

	qname := "_acme-reg." + testAcmeDigest + "." + exampleZone
	resp := serveDNS(t, a, "100.64.0.10", qname, dns.TypeTXT)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("publish rcode = %d, want success", resp.Rcode)
	}

	stored := mr.HGet(zoneKey, "_acme-challenge")
	if !strings.Contains(stored, testAcmeDigest) {
		t.Fatalf("redis = %q, want digest", stored)
	}

	public := serveDNS(t, a, "8.8.8.8", "_acme-challenge."+exampleZone, dns.TypeTXT)
	if public.Rcode != dns.RcodeSuccess {
		t.Fatalf("public lookup rcode = %d", public.Rcode)
	}
	tc := test.Case{
		Qname:  "_acme-challenge." + exampleZone,
		Qtype:  dns.TypeTXT,
		Answer: []dns.RR{test.TXT(`_acme-challenge.example.net. 120 IN TXT "` + testAcmeDigest + `"`)},
	}
	if err := test.SortAndCheck(public, tc); err != nil {
		t.Error(err)
	}
}

func TestAcmeRotateMultipleApexDigests(t *testing.T) {
	a, mr := acmeAutodns(t)
	zoneKey := a.keyPrefix + exampleZone + a.keySuffix

	q1 := "_acme-reg." + testAcmeDigest + "." + exampleZone
	q2 := "_acme-reg." + testAcmeDigest2 + "." + exampleZone
	if resp := serveDNS(t, a, "100.64.0.10", q1, dns.TypeTXT); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("first publish rcode = %d", resp.Rcode)
	}
	if resp := serveDNS(t, a, "100.64.0.10", q2, dns.TypeTXT); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("second publish rcode = %d", resp.Rcode)
	}

	stored := mr.HGet(zoneKey, "_acme-challenge")
	if !strings.Contains(stored, testAcmeDigest) || !strings.Contains(stored, testAcmeDigest2) {
		t.Fatalf("redis must keep both digests, got %q", stored)
	}

	public := serveDNS(t, a, "8.8.8.8", "_acme-challenge."+exampleZone, dns.TypeTXT)
	if len(public.Answer) != 2 {
		t.Fatalf("public answer count = %d, want 2 TXT records", len(public.Answer))
	}
}

func TestAcmeRotateOverflow(t *testing.T) {
	a, _ := acmeAutodns(t)
	a.AcmeRotate = 3

	digests := []string{
		"digest0001ABC-_def456GHI789jkl012MNO345",
		"digest0002ABC-_def456GHI789jkl012MNO345",
		"digest0003ABC-_def456GHI789jkl012MNO345",
		"digest0004ABC-_def456GHI789jkl012MNO345",
	}
	for _, d := range digests {
		qname := "_acme-reg." + d + "." + exampleZone
		if resp := serveDNS(t, a, "100.64.0.10", qname, dns.TypeTXT); resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("publish %q rcode = %d", d, resp.Rcode)
		}
	}

	public := serveDNS(t, a, "8.8.8.8", "_acme-challenge."+exampleZone, dns.TypeTXT)
	if len(public.Answer) != 3 {
		t.Fatalf("answer count = %d, want 3 after rotate", len(public.Answer))
	}
	texts := make(map[string]bool)
	for _, rr := range public.Answer {
		txt := rr.(*dns.TXT)
		texts[strings.Join(txt.Txt, "")] = true
	}
	if texts[digests[0]] {
		t.Fatal("oldest digest should have been rotated out")
	}
	for _, d := range digests[1:] {
		if !texts[d] {
			t.Fatalf("expected digest %q in answer", d)
		}
	}
}

func TestAppendAcmeTXT(t *testing.T) {
	ttl := uint32(120)
	txts := appendAcmeTXT(nil, testAcmeDigest, ttl, 5)
	if len(txts) != 1 || txts[0].Text != testAcmeDigest {
		t.Fatalf("first append = %+v", txts)
	}
	txts = appendAcmeTXT(txts, testAcmeDigest2, ttl, 5)
	if len(txts) != 2 {
		t.Fatalf("len = %d, want 2", len(txts))
	}
	txts = appendAcmeTXT(txts, testAcmeDigest, ttl, 5)
	if len(txts) != 2 || txts[1].Text != testAcmeDigest {
		t.Fatalf("republish should move digest to end without duplicate, got %+v", txts)
	}
}

func TestAcmeDeleteSingleDigest(t *testing.T) {
	a, mr := acmeAutodns(t)
	zoneKey := a.keyPrefix + exampleZone + a.keySuffix

	for _, d := range []string{testAcmeDigest, testAcmeDigest2} {
		qname := "_acme-reg." + d + "." + exampleZone
		if resp := serveDNS(t, a, "100.64.0.10", qname, dns.TypeTXT); resp.Rcode != dns.RcodeSuccess {
			t.Fatal("publish failed")
		}
	}

	del := "_acme-del." + testAcmeDigest + "." + exampleZone
	if resp := serveDNS(t, a, "100.64.0.10", del, dns.TypeTXT); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("delete rcode = %d", resp.Rcode)
	}
	stored := mr.HGet(zoneKey, "_acme-challenge")
	if strings.Contains(stored, testAcmeDigest) {
		t.Fatalf("removed digest still in redis: %q", stored)
	}
	if !strings.Contains(stored, testAcmeDigest2) {
		t.Fatalf("other digest should remain: %q", stored)
	}

	public := serveDNS(t, a, "8.8.8.8", "_acme-challenge."+exampleZone, dns.TypeTXT)
	if len(public.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(public.Answer))
	}
}

func TestAcmeRegistrationHost(t *testing.T) {
	a, mr := acmeAutodns(t)
	zoneKey := a.keyPrefix + exampleZone + a.keySuffix

	qname := "_acme-reg." + testAcmeDigest + ".host1." + exampleZone
	resp := serveDNS(t, a, "100.64.0.10", qname, dns.TypeTXT)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("publish rcode = %d, want success", resp.Rcode)
	}

	stored := mr.HGet(zoneKey, "_acme-challenge.host1")
	if !strings.Contains(stored, testAcmeDigest) {
		t.Fatalf("redis = %q, want digest", stored)
	}

	public := serveDNS(t, a, "8.8.8.8", "_acme-challenge.host1."+exampleZone, dns.TypeTXT)
	tc := test.Case{
		Qname:  "_acme-challenge.host1." + exampleZone,
		Qtype:  dns.TypeTXT,
		Answer: []dns.RR{test.TXT(`_acme-challenge.host1.example.net. 120 IN TXT "` + testAcmeDigest + `"`)},
	}
	if err := test.SortAndCheck(public, tc); err != nil {
		t.Error(err)
	}
}

func TestAcmeRegistrationDenied(t *testing.T) {
	a, mr := acmeAutodns(t)
	zoneKey := a.keyPrefix + exampleZone + a.keySuffix

	qname := "_acme-reg." + testAcmeDigest + ".host1." + exampleZone
	resp := serveDNS(t, a, "10.0.0.1", qname, dns.TypeTXT)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", resp.Rcode)
	}
	if stored := mr.HGet(zoneKey, "_acme-challenge.host1"); stored != "" {
		t.Fatalf("denied request must not write redis, got %q", stored)
	}
}

// TestServeDNSAcmeDeny verifies README acme.deny names cannot publish via _acme-reg.*.
func TestServeDNSAcmeDeny(t *testing.T) {
	a, mr := acmeAutodns(t)
	a.AcmeDeny = readmeAcmeDeny
	zoneKey := a.keyPrefix + exampleZone + a.keySuffix

	for _, label := range readmeAcmeDeny {
		t.Run(label, func(t *testing.T) {
			mr.HDel(zoneKey, "_acme-challenge."+label)
			qname := "_acme-reg." + testAcmeDigest + "." + label + "." + exampleZone
			resp := serveDNS(t, a, "100.64.0.10", qname, dns.TypeTXT)
			if resp.Rcode != dns.RcodeNameError {
				t.Fatalf("rcode = %d, want NXDOMAIN for %q", resp.Rcode, label)
			}
			if stored := mr.HGet(zoneKey, "_acme-challenge."+label); stored != "" {
				t.Fatalf("denied ACME publish must not write redis for %q, got %q", label, stored)
			}
		})
	}

	t.Run("apex with @", func(t *testing.T) {
		a.AcmeDeny = []string{"@"}
		mr.HDel(zoneKey, "_acme-challenge")
		qname := "_acme-reg." + testAcmeDigest + "." + exampleZone
		resp := serveDNS(t, a, "100.64.0.10", qname, dns.TypeTXT)
		if resp.Rcode != dns.RcodeNameError {
			t.Fatalf("rcode = %d, want NXDOMAIN for apex wildcard", resp.Rcode)
		}
		if stored := mr.HGet(zoneKey, "_acme-challenge"); stored != "" {
			t.Fatalf("denied apex ACME must not write redis, got %q", stored)
		}
	})
}

func TestAcmeRegistrationInvalidDigest(t *testing.T) {
	a, mr := acmeAutodns(t)
	zoneKey := a.keyPrefix + exampleZone + a.keySuffix

	qname := "_acme-reg.invalid*chars.host1." + exampleZone
	resp := serveDNS(t, a, "100.64.0.10", qname, dns.TypeTXT)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", resp.Rcode)
	}
	if stored := mr.HGet(zoneKey, "_acme-challenge.host1"); stored != "" {
		t.Fatalf("invalid digest must not write redis, got %q", stored)
	}
}

func TestAcmeDeletion(t *testing.T) {
	a, mr := acmeAutodns(t)
	zoneKey := a.keyPrefix + exampleZone + a.keySuffix

	publish := "_acme-reg." + testAcmeDigest + ".host1." + exampleZone
	if resp := serveDNS(t, a, "100.64.0.10", publish, dns.TypeTXT); resp.Rcode != dns.RcodeSuccess {
		t.Fatal("publish failed")
	}

	del := "_acme-del.host1." + exampleZone
	resp := serveDNS(t, a, "100.64.0.10", del, dns.TypeTXT)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("delete rcode = %d, want success", resp.Rcode)
	}
	if stored := mr.HGet(zoneKey, "_acme-challenge.host1"); stored != "" {
		t.Fatalf("expected field deleted, got %q", stored)
	}

	public := serveDNS(t, a, "8.8.8.8", "_acme-challenge.host1."+exampleZone, dns.TypeTXT)
	if public.Rcode != dns.RcodeNameError {
		t.Fatalf("public lookup after delete rcode = %d, want NXDOMAIN", public.Rcode)
	}
}

func TestAcmeRegistrationNonTXT(t *testing.T) {
	a, mr := acmeAutodns(t)
	zoneKey := a.keyPrefix + exampleZone + a.keySuffix
	qname := "_acme-reg." + testAcmeDigest + ".host1." + exampleZone

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			mr.HDel(zoneKey, "_acme-challenge.host1")
			resp := serveDNS(t, a, "100.64.0.10", qname, qtype)
			if resp.Rcode != dns.RcodeNameError {
				t.Fatalf("rcode = %d, want NXDOMAIN", resp.Rcode)
			}
			if stored := mr.HGet(zoneKey, "_acme-challenge.host1"); stored != "" {
				t.Fatalf("non-TXT must not write redis, got %q", stored)
			}
		})
	}
}

func TestAcmeUsesRegisterNetworkFallback(t *testing.T) {
	a, mr := newTestAutodns(t, func(a *Autodns) {
		a.RegisterNetworks = mustParseCIDRs(t, "100.64.0.0/16")
	})
	seedRegistrationZone(t, mr, a)

	qname := "_acme-reg." + testAcmeDigest + ".host1." + exampleZone
	resp := serveDNS(t, a, "100.64.0.10", qname, dns.TypeTXT)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want success when falling back to register.network", resp.Rcode)
	}
}

func mustParseCIDRs(t *testing.T, cidrs ...string) []net.IPNet {
	t.Helper()
	nets := make([]net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		nets = append(nets, *ipNet)
	}
	return nets
}
