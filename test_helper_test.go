package autodns

import (
	"net"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

const exampleZone = "example.net."

// readmeRegisterDeny matches the register.deny labels documented in README.md.
var readmeRegisterDeny = []string{"ns1", "ns2", "ns3", "www"}

// readmeAcmeDeny matches the acme.deny labels documented in README.md.
var readmeAcmeDeny = []string{"ns1", "ns2", "ns3", "www"}

func newTestAutodns(t *testing.T, opts ...func(*Autodns)) (*Autodns, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)
	a := &Autodns{
		redisAddress:   mr.Addr(),
		Ttl:            300,
		LastZoneUpdate: time.Now(),
	}
	a.Connect()

	for _, opt := range opts {
		opt(a)
	}

	return a, mr
}

func seedExampleZone(t *testing.T, mr *miniredis.Miniredis, a *Autodns) {
	t.Helper()

	zoneKey := a.keyPrefix + exampleZone + a.keySuffix
	entries := map[string]string{
		"_ssh._tcp.host1": `{"srv":[{"ttl":300, "target":"tcp.example.com.","port":123,"priority":10,"weight":100}]}`,
		"*":               `{"txt":[{"ttl":300, "text":"this is a wildcard"}],"mx":[{"ttl":300, "host":"host1.example.net.","preference": 10}]}`,
		"host1":           `{"a":[{"ttl":300, "ip":"5.5.5.5"}]}`,
		"sub.*":           `{"txt":[{"ttl":300, "text":"this is not a wildcard"}]}`,
		"_ssh._tcp.host2": `{"srv":[{"ttl":300, "target":"tcp.example.com.","port":123,"priority":10,"weight":100}]}`,
		"subdel":          `{"ns":[{"ttl":300, "host":"ns1.subdel.example.net."},{"ttl":300, "host":"ns2.subdel.example.net."}]}`,
		"@":               `{"soa":{"ttl":300, "minttl":100, "mbox":"hostmaster.example.net.","ns":"ns1.example.net.","refresh":44,"retry":55,"expire":66},"ns":[{"ttl":300, "host":"ns1.example.net."},{"ttl":300, "host":"ns2.example.net."}]}`,
		"host2":           `{"caa":[{"flag":0, "tag":"issue", "value":"letsencrypt.org"}]}`,
	}

	for field, value := range entries {
		mr.HSet(zoneKey, field, value)
	}

	a.Zones = []string{exampleZone}
}

type remoteAddrWriter struct {
	dns.ResponseWriter
	addr net.Addr
}

func (w *remoteAddrWriter) RemoteAddr() net.Addr {
	return w.addr
}

func newRecorderWithIP(t *testing.T, ip string) *dnstest.Recorder {
	t.Helper()

	base := &test.ResponseWriter{RemoteIP: ip}
	return dnstest.NewRecorder(&remoteAddrWriter{
		ResponseWriter: base,
		addr:           base.RemoteAddr(),
	})
}

func prepareServeDNS(t *testing.T, opts ...func(*Autodns)) (*Autodns, *miniredis.Miniredis) {
	t.Helper()

	a, mr := newTestAutodns(t, opts...)
	seedExampleZone(t, mr, a)
	return a, mr
}
