package autodns

import (
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

func (autodns *Autodns) TXT(name string, z *Zone, record *Record) (answers, extras []dns.RR) {
	for _, txt := range record.TXT {
		if len(txt.Text) == 0 {
			continue
		}
		r := new(dns.TXT)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeTXT,
			Class: dns.ClassINET, Ttl: autodns.minTtl(txt.Ttl)}
		r.Txt = split255(txt.Text)
		answers = append(answers, r)
	}
	return
}

func (autodns *Autodns) TXTReply(name string, reply []string, resp *dns.Msg, state *request.Request, w dns.ResponseWriter) (int, error) {
	answers := make([]dns.RR, 0, 10)
	extras := make([]dns.RR, 0, 10)
	r := new(dns.TXT)
	r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeTXT,
		Class: dns.ClassINET, Ttl: autodns.minTtl(60)}
	r.Txt = reply
	answers = append(answers, r)

	m := new(dns.Msg)
	m.SetReply(resp)
	m.Authoritative, m.RecursionAvailable, m.Compress = true, false, true

	m.Answer = append(m.Answer, answers...)
	m.Extra = append(m.Extra, extras...)

	state.SizeAndDo(m)
	m = state.Scrub(m)
	_ = w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}
