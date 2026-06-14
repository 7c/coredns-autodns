package autodns

import (
	"fmt"
	"net"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/coredns/caddy"
)

func TestRedisSetup(t *testing.T) {
	mr := miniredis.RunT(t)
	corefile := fmt.Sprintf(`autodns {
		address %s
		password secret
		prefix dns:
		suffix :zone
		ttl 600
		verbose
		register.network 100.64.0.0/16
		register.deny www
	}`, mr.Addr())

	c := caddy.NewTestController("dns", corefile)
	a, err := redisSetup(c)
	if err != nil {
		t.Fatalf("redisSetup error: %v", err)
	}

	if a.redisAddress != mr.Addr() {
		t.Fatalf("address = %q, want %q", a.redisAddress, mr.Addr())
	}
	if a.redisPassword != "secret" {
		t.Fatalf("password = %q, want secret", a.redisPassword)
	}
	if a.keyPrefix != "dns:" || a.keySuffix != ":zone" {
		t.Fatalf("prefix/suffix = %q / %q", a.keyPrefix, a.keySuffix)
	}
	if a.Ttl != 600 {
		t.Fatalf("ttl = %d, want 600", a.Ttl)
	}
	if !a.Verbose {
		t.Fatal("expected verbose=true")
	}
	if len(a.RegisterDeny) != 1 || a.RegisterDeny[0] != "www" {
		t.Fatalf("RegisterDeny = %v", a.RegisterDeny)
	}
	if len(a.RegisterNetworks) != 1 {
		t.Fatalf("RegisterNetworks = %v", a.RegisterNetworks)
	}
	if !a.RegisterNetworks[0].Contains(net.ParseIP("100.64.0.1")) {
		t.Fatal("expected 100.64.0.0/16 in RegisterNetworks")
	}
}

func TestRedisSetupErrors(t *testing.T) {
	mr := miniredis.RunT(t)

	tests := []struct {
		name      string
		corefile  string
		wantError bool
	}{
		{
			name: "unknown directive",
			corefile: fmt.Sprintf(`autodns {
				address %s
				unknown_option
			}`, mr.Addr()),
			wantError: true,
		},
		{
			name: "invalid CIDR",
			corefile: fmt.Sprintf(`autodns {
				address %s
				register.network not-a-cidr
			}`, mr.Addr()),
			wantError: true,
		},
		{
			name: "missing address arg",
			corefile: `autodns {
				address
			}`,
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.corefile)
			_, err := redisSetup(c)
			if tc.wantError && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRedisSetupRegisterNetworks(t *testing.T) {
	mr := miniredis.RunT(t)
	corefile := fmt.Sprintf(`autodns {
		address %s
		register.network 100.64.0.0/16
		register.network 127.0.0.1/32
	}`, mr.Addr())

	c := caddy.NewTestController("dns", corefile)
	a, err := redisSetup(c)
	if err != nil {
		t.Fatalf("redisSetup error: %v", err)
	}
	if len(a.RegisterNetworks) != 2 {
		t.Fatalf("RegisterNetworks = %d entries, want 2", len(a.RegisterNetworks))
	}
	if !a.RegisterNetworks[0].Contains(net.ParseIP("100.64.0.1")) {
		t.Fatal("expected first network 100.64.0.0/16")
	}
	if !a.RegisterNetworks[1].Contains(net.ParseIP("127.0.0.1")) {
		t.Fatal("expected second network 127.0.0.1/32")
	}
}

func TestAcmeSetup(t *testing.T) {
	mr := miniredis.RunT(t)
	corefile := fmt.Sprintf(`autodns {
		address %s
		acme.network 100.64.0.0/16 fd00::/8
		acme.ttl 90
	}`, mr.Addr())

	c := caddy.NewTestController("dns", corefile)
	a, err := redisSetup(c)
	if err != nil {
		t.Fatalf("redisSetup error: %v", err)
	}
	if len(a.AcmeNetworks) != 2 {
		t.Fatalf("AcmeNetworks = %d, want 2", len(a.AcmeNetworks))
	}
	if a.AcmeTtl != 90 {
		t.Fatalf("AcmeTtl = %d, want 90", a.AcmeTtl)
	}
}

func TestRedisSetupAcmeDeny(t *testing.T) {
	mr := miniredis.RunT(t)
	corefile := fmt.Sprintf(`autodns {
		address %s
		acme.deny ns1
		acme.deny ns2
		acme.deny ns3
		acme.deny www
	}`, mr.Addr())

	c := caddy.NewTestController("dns", corefile)
	a, err := redisSetup(c)
	if err != nil {
		t.Fatalf("redisSetup error: %v", err)
	}
	if len(a.AcmeDeny) != len(readmeAcmeDeny) {
		t.Fatalf("AcmeDeny = %v, want %v", a.AcmeDeny, readmeAcmeDeny)
	}
	for i, label := range readmeAcmeDeny {
		if a.AcmeDeny[i] != label {
			t.Fatalf("AcmeDeny[%d] = %q, want %q", i, a.AcmeDeny[i], label)
		}
	}
}

func TestRedisSetupRegisterDeny(t *testing.T) {
	mr := miniredis.RunT(t)
	corefile := fmt.Sprintf(`autodns {
		address %s
		register.deny ns1
		register.deny ns2
		register.deny ns3
		register.deny www
	}`, mr.Addr())

	c := caddy.NewTestController("dns", corefile)
	a, err := redisSetup(c)
	if err != nil {
		t.Fatalf("redisSetup error: %v", err)
	}
	if len(a.RegisterDeny) != len(readmeRegisterDeny) {
		t.Fatalf("RegisterDeny = %v, want %v", a.RegisterDeny, readmeRegisterDeny)
	}
	for i, label := range readmeRegisterDeny {
		if a.RegisterDeny[i] != label {
			t.Fatalf("RegisterDeny[%d] = %q, want %q", i, a.RegisterDeny[i], label)
		}
	}
}

func TestRedisSetupRegisterNetworksCombinedLine(t *testing.T) {
	mr := miniredis.RunT(t)
	corefile := fmt.Sprintf(`autodns {
		address %s
		register.network 100.64.0.0/16 127.0.0.1/32 fd00::/8
	}`, mr.Addr())

	c := caddy.NewTestController("dns", corefile)
	a, err := redisSetup(c)
	if err != nil {
		t.Fatalf("redisSetup error: %v", err)
	}
	if len(a.RegisterNetworks) != 3 {
		t.Fatalf("RegisterNetworks = %d entries, want 3", len(a.RegisterNetworks))
	}
	if !a.RegisterNetworks[0].Contains(net.ParseIP("100.64.0.1")) {
		t.Fatal("expected 100.64.0.0/16")
	}
	if !a.RegisterNetworks[1].Contains(net.ParseIP("127.0.0.1")) {
		t.Fatal("expected 127.0.0.1/32")
	}
	if !a.RegisterNetworks[2].Contains(net.ParseIP("fd00::10")) {
		t.Fatal("expected fd00::/8")
	}
}

func TestRedisSetupDirectives(t *testing.T) {
	mr := miniredis.RunT(t)
	corefile := fmt.Sprintf(`autodns {
		address %s
		connect_timeout 500
		read_timeout 250
		autocreate newzone.example
	}`, mr.Addr())

	c := caddy.NewTestController("dns", corefile)
	a, err := redisSetup(c)
	if err != nil {
		t.Fatalf("redisSetup error: %v", err)
	}
	if a.connectTimeout != 500 {
		t.Fatalf("connect_timeout = %d, want 500", a.connectTimeout)
	}
	if a.readTimeout != 250 {
		t.Fatalf("read_timeout = %d, want 250", a.readTimeout)
	}
	if len(a.AutoCreate) != 1 || a.AutoCreate[0] != "newzone.example" {
		t.Fatalf("AutoCreate = %v", a.AutoCreate)
	}
}
