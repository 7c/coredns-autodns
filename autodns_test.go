package autodns

import (
	"net"
	"strings"
	"testing"
)

func TestIPBelongsToRegisterNetworks(t *testing.T) {
	_, net100, err := net.ParseCIDR("100.64.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	_, net127, err := net.ParseCIDR("127.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	_, netUla, err := net.ParseCIDR("fd00::/8")
	if err != nil {
		t.Fatal(err)
	}
	networks := []net.IPNet{*net100, *net127, *netUla}

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{name: "inside first CIDR", ip: "100.64.0.1", want: true},
		{name: "inside second CIDR", ip: "127.0.0.1", want: true},
		{name: "inside IPv6 ULA", ip: "fd00::10", want: true},
		{name: "outside all CIDRs", ip: "10.0.0.1", want: false},
		{name: "just outside tailscale range", ip: "100.65.0.1", want: false},
		{name: "loopback neighbor denied", ip: "127.0.0.2", want: false},
		{name: "outside IPv6 ULA", ip: "2001:db8::1", want: false},
		{name: "nil IP", ip: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ip net.IP
			if tc.ip != "" {
				ip = net.ParseIP(tc.ip)
			}
			if got := IPBelongsToRegisterNetworks(ip, networks); got != tc.want {
				t.Fatalf("IPBelongsToRegisterNetworks(%v) = %v, want %v", ip, got, tc.want)
			}
		})
	}

	t.Run("empty network list", func(t *testing.T) {
		if IPBelongsToRegisterNetworks(net.ParseIP("100.64.0.1"), nil) {
			t.Fatal("expected false for empty network list")
		}
	})
}

func TestSubdomainBelongsToDeny(t *testing.T) {
	a := &Autodns{RegisterDeny: readmeRegisterDeny}

	tests := []struct {
		name      string
		subdomain string
		want      bool
	}{
		{name: "denied www", subdomain: "www", want: true},
		{name: "denied ns1", subdomain: "ns1", want: true},
		{name: "denied ns2", subdomain: "ns2", want: true},
		{name: "denied ns3", subdomain: "ns3", want: true},
		{name: "allowed host1", subdomain: "host1", want: false},
		{name: "case sensitive no match", subdomain: "WWW", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.subdomainBelongsToDeny(tc.subdomain); got != tc.want {
				t.Fatalf("subdomainBelongsToDeny(%q) = %v, want %v", tc.subdomain, got, tc.want)
			}
		})
	}
}

func TestAcmeHostBelongsToDeny(t *testing.T) {
	a := &Autodns{AcmeDeny: readmeAcmeDeny}

	tests := []struct {
		name      string
		hostLabel string
		want      bool
	}{
		{name: "denied www", hostLabel: "www", want: true},
		{name: "denied ns1", hostLabel: "ns1", want: true},
		{name: "denied ns2", hostLabel: "ns2", want: true},
		{name: "denied ns3", hostLabel: "ns3", want: true},
		{name: "allowed host1", hostLabel: "host1", want: false},
		{name: "allowed apex", hostLabel: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.acmeHostBelongsToDeny(tc.hostLabel); got != tc.want {
				t.Fatalf("acmeHostBelongsToDeny(%q) = %v, want %v", tc.hostLabel, got, tc.want)
			}
		})
	}

	t.Run("denied apex with @", func(t *testing.T) {
		apex := &Autodns{AcmeDeny: []string{"@"}}
		if !apex.acmeHostBelongsToDeny("") {
			t.Fatal("expected apex wildcard to be denied with @")
		}
	})
}

func TestMinTtl(t *testing.T) {
	tests := []struct {
		name       string
		pluginTtl  uint32
		recordTtl  uint32
		want       uint32
	}{
		{name: "both zero uses default", pluginTtl: 0, recordTtl: 0, want: defaultTtl},
		{name: "plugin default only", pluginTtl: 300, recordTtl: 0, want: 300},
		{name: "record only", pluginTtl: 0, recordTtl: 600, want: 600},
		{name: "minimum of both", pluginTtl: 300, recordTtl: 600, want: 300},
		{name: "record lower than plugin", pluginTtl: 600, recordTtl: 300, want: 300},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := &Autodns{Ttl: tc.pluginTtl}
			if got := a.minTtl(tc.recordTtl); got != tc.want {
				t.Fatalf("minTtl(%d) with plugin Ttl %d = %d, want %d", tc.recordTtl, tc.pluginTtl, got, tc.want)
			}
		})
	}
}

func TestSplit255(t *testing.T) {
	short := "hello"
	if got := split255(short); len(got) != 1 || got[0] != short {
		t.Fatalf("split255 short: got %v", got)
	}

	exact255 := strings.Repeat("a", 254)
	if got := split255(exact255); len(got) != 1 || got[0] != exact255 {
		t.Fatalf("split255(254): got %v", got)
	}

	long := strings.Repeat("b", 300)
	got := split255(long)
	if len(got) != 2 {
		t.Fatalf("split255(300): got %d chunks, want 2", len(got))
	}
	if len(got[0]) != 255 || len(got[1]) != 45 {
		t.Fatalf("split255(300): chunk lengths %d and %d", len(got[0]), len(got[1]))
	}
}

func TestSplitQuery(t *testing.T) {
	tests := []struct {
		name              string
		query             string
		wantEncloser      string
		wantSynthesis     string
		wantOk            bool
	}{
		{name: "empty", query: "", wantEncloser: "", wantSynthesis: "", wantOk: false},
		{name: "single label", query: "foo", wantEncloser: "", wantSynthesis: "*", wantOk: true},
		{name: "multi label", query: "bar.sub.foo", wantEncloser: "sub.foo", wantSynthesis: "*.sub.foo", wantOk: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ce, ss, ok := splitQuery(tc.query)
			if ok != tc.wantOk {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOk)
			}
			if ce != tc.wantEncloser || ss != tc.wantSynthesis {
				t.Fatalf("splitQuery(%q) = (%q, %q), want (%q, %q)", tc.query, ce, ss, tc.wantEncloser, tc.wantSynthesis)
			}
		})
	}
}

func exampleLocations() map[string]struct{} {
	return map[string]struct{}{
		"@":     {},
		"host1": {},
		"*":     {},
		"sub.*": {},
	}
}

func TestFindLocation(t *testing.T) {
	a := &Autodns{Ttl: 300}
	z := &Zone{Name: exampleZone, Locations: exampleLocations()}

	tests := []struct {
		name  string
		query string
		want  string
	}{
		{name: "apex", query: exampleZone, want: exampleZone},
		{name: "exact host1", query: "host1.example.net.", want: "host1"},
		{name: "wildcard star", query: "foo.example.net.", want: "*"},
		{name: "nested wildcard sub star", query: "bar.sub.foo.example.net.", want: "*"},
		{name: "no match without star", query: "nonexistent.example.net.", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			zone := z
			if tc.name == "no match without star" {
				zone = &Zone{Name: exampleZone, Locations: map[string]struct{}{"host1": {}, "@": {}}}
			}
			if got := a.findLocation(tc.query, zone); got != tc.want {
				t.Fatalf("findLocation(%q) = %q, want %q", tc.query, got, tc.want)
			}
		})
	}
}
