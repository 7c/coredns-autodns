package autodns

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

func (autodns *Autodns) AddARecord(zone string, subdomain string, ip string) error {
	// redis
	conn := autodns.Pool.Get()
	if conn == nil {
		return errors.New("error connecting to redis")
	}
	defer conn.Close()

	// add the record to redis
	_, err := conn.Do("HSET", autodns.keyPrefix+zone+autodns.keySuffix, subdomain, `{"a": [{"ip": "`+ip+`", "ttl": `+strconv.Itoa(int(autodns.Ttl))+`}]}`)
	if err != nil {
		return err
	}
	logger.Info(`Added A record to redis for `, subdomain, ` with ip `, ip, ` and ttl `, autodns.Ttl)
	return nil
}

// ServeDNS implements the plugin.Handler interface.
func (autodns *Autodns) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	clientIP := strings.Split(w.RemoteAddr().String(), ":")[0]

	qname := state.Name()
	qname = strings.TrimSpace(qname)
	qname = strings.ToLower(qname)
	qtype := state.Type()

	if autodns.Verbose {
		logger.Info(fmt.Sprintf("%s - [query] '%s' '%s'", clientIP, qtype, qname))
	}

	if time.Since(autodns.LastZoneUpdate) > zoneUpdateTime {
		autodns.LoadZones()
	}

	// we need to be responsible for the zone
	zone := plugin.Zones(autodns.Zones).Matches(qname)
	if zone == "" {
		return plugin.NextOrFailure(qname, autodns.Next, ctx, w, r)
	}

	// load the zone from redis
	z := autodns.load(zone)
	if z == nil {
		return autodns.errorResponse(state, zone, dns.RcodeServerFailure, nil)
	}

	if qtype == "AXFR" {

		records := autodns.AXFR(z)

		ch := make(chan *dns.Envelope)
		tr := new(dns.Transfer)
		tr.TsigSecret = nil

		go func(ch chan *dns.Envelope) {
			j, l := 0, 0

			for i, r := range records {
				l += dns.Len(r)
				if l > transferLength {
					ch <- &dns.Envelope{RR: records[j:i]}
					l = 0
					j = i
				}
			}
			if j < len(records) {
				ch <- &dns.Envelope{RR: records[j:]}
			}
			close(ch)
		}(ch)

		err := tr.Out(w, r, ch)
		if err != nil {
			fmt.Println(err)
		}
		w.Hijack()
		return dns.RcodeSuccess, nil
	}

	location := autodns.findLocation(qname, z)
	if len(location) == 0 {
		// empty, no results from this zone about that rr
		// _reg requests are normally not part of the zone

		if qtype == "TXT" && strings.HasPrefix(qname, "_reg.") {
			if IPBelongsToRegisterNetworks(net.ParseIP(clientIP), autodns.RegisterNetworks) { // acl for registration sepeate from acl{}
				parts := strings.SplitN(qname, ".", 3)
				// first part is _reg keyword
				// example: _reg.s3.example.com
				// example: _reg.www.s3.example.com
				// _reg.<fullhost>
				// _reg.<subdomain>.<zone>
				if len(parts) >= 3 {
					fullhost := strings.Join(parts[1:], ".")
					// remove zone from fullhost
					subdomain := strings.TrimSuffix(fullhost, "."+zone)
					if slices.Contains(autodns.RegisterDeny, subdomain) {
						logger.Warning(`Registration request for `, qname, ` from `, clientIP, ` denied because of register.deny setting`)
						return autodns.errorResponse(state, zone, dns.RcodeNameError, nil)
					}
					logger.Info(`Registration request for fullhost: `, fullhost, ` subdomain: `, subdomain, ` ip: `, clientIP)
					if err := autodns.AddARecord(zone, subdomain, clientIP); err != nil {
						logger.Error(`Error adding A record to redis for `, subdomain, ` with ip `, clientIP, ` and ttl `, autodns.Ttl, ` error: `, err)
					}
					logger.Info(`Registration success for `, qname, ` from `, clientIP)
					if _, err := autodns.TXTReply(qname, []string{fmt.Sprintf("%s", strings.TrimSuffix(fullhost, "."))}, r, &state, w); err != nil {
						logger.Error(`Error sending TXT reply for `, qname, ` error: `, err)
						return autodns.errorResponse(state, zone, dns.RcodeServerFailure, err)
					}
					return dns.RcodeSuccess, nil
				}
			} else {
				logger.Warning(`Registration request for `, qname, ` from `, clientIP, ` not in register networks`)
				return autodns.errorResponse(state, zone, dns.RcodeNameError, nil)
			}
		}

		return autodns.errorResponse(state, zone, dns.RcodeNameError, nil)
	}

	answers := make([]dns.RR, 0, 10)
	extras := make([]dns.RR, 0, 10)

	record := autodns.get(location, z)

	switch qtype {
	case "A":
		answers, extras = autodns.A(qname, z, record)
	case "AAAA":
		answers, extras = autodns.AAAA(qname, z, record)
	case "CNAME":
		answers, extras = autodns.CNAME(qname, z, record)
	case "TXT":
		answers, extras = autodns.TXT(qname, z, record)
	case "NS":
		answers, extras = autodns.NS(qname, z, record)
	case "MX":
		answers, extras = autodns.MX(qname, z, record)
	case "SRV":
		answers, extras = autodns.SRV(qname, z, record)
	case "SOA":
		answers, extras = autodns.SOA(qname, z, record)
	case "CAA":
		answers, extras = autodns.CAA(qname, z, record)

	default:
		return autodns.errorResponse(state, zone, dns.RcodeNotImplemented, nil)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative, m.RecursionAvailable, m.Compress = true, false, true

	m.Answer = append(m.Answer, answers...)
	m.Extra = append(m.Extra, extras...)

	state.SizeAndDo(m)
	m = state.Scrub(m)
	_ = w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

// Name implements the Handler interface.
func (autodns *Autodns) Name() string { return "autodns" }

func (autodns *Autodns) errorResponse(state request.Request, zone string, rcode int, err error) (int, error) {
	m := new(dns.Msg)
	m.SetRcode(state.Req, rcode)
	m.Authoritative, m.RecursionAvailable, m.Compress = true, false, true

	state.SizeAndDo(m)
	_ = state.W.WriteMsg(m)
	// Return success as the rcode to signal we have written to the client.
	return dns.RcodeSuccess, err
}
