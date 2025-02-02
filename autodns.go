package autodns

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/coredns/coredns/plugin"

	redisCon "github.com/gomodule/redigo/redis"
)

type Autodns struct {
	Next             plugin.Handler
	Pool             *redisCon.Pool
	redisAddress     string
	redisPassword    string
	connectTimeout   int
	readTimeout      int
	keyPrefix        string
	keySuffix        string
	Ttl              uint32
	Zones            []string
	Verbose          bool
	AutoCreate       []string
	LastZoneUpdate   time.Time
	RegisterNetworks []net.IPNet
	RegisterDeny     []string
}

func IPBelongsToRegisterNetworks(ip net.IP, networks []net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (autodns *Autodns) subdomainBelongsToDeny(subdomain string) bool {
	for _, deny := range autodns.RegisterDeny {
		if deny == subdomain {
			return true
		}
	}
	return false
}

func (autodns *Autodns) CreateZone(zone string) error {
	conn := autodns.Pool.Get()
	if conn == nil {
		fmt.Println("error connecting to redis")
		return errors.New("error connecting to redis")
	}
	defer conn.Close()
	zone = UniformZone(zone)

	r2 := Native_SOA_Record{}
	r2.SOA.Ns = "ns1." + zone
	r2.SOA.MBox = "hostmaster." + zone
	r2.SOA.Refresh = 86400
	r2.SOA.Retry = 7200
	r2.SOA.Expire = 3600
	r2.SOA.MinTtl = autodns.Ttl
	if soa, _ := json.Marshal(r2); len(soa) > 0 {
		//HSET _dns:test.com. @ '{"soa": {"mname": "ns1.test.com.", "rname": "hostmaster.test.com.", "serial": 2024012901, "refresh": 7200, "retry": 3600, "expire": 1209600, "minimum": 3600}}'
		_, err := conn.Do("HSET", autodns.keyPrefix+zone+autodns.keySuffix, "@", soa)
		if err != nil {
			fmt.Println("error creating zone: ", err)
			return err
		}
		fmt.Printf("zone %s SOA created\n", zone)
	}
	return nil
}

func (autodns *Autodns) LoadZones() {
	var (
		reply interface{}
		err   error
		zones []string
	)

	conn := autodns.Pool.Get()
	if conn == nil {
		fmt.Println("error connecting to redis")
		return
	}
	defer conn.Close()

	reply, err = conn.Do("KEYS", autodns.keyPrefix+"*"+autodns.keySuffix)
	if err != nil {
		return
	}
	zones, _ = redisCon.Strings(reply, nil)
	for i := range zones {
		zones[i] = strings.TrimPrefix(zones[i], autodns.keyPrefix)
		zones[i] = strings.TrimSuffix(zones[i], autodns.keySuffix)
	}
	// go over autocreate and create zones if they don't exist
	for _, zone := range autodns.AutoCreate {
		zone = UniformZone(zone)
		if !contains(zones, zone) {
			if err := autodns.CreateZone(zone); err != nil {
				logger.Info("error creating zone: ", err)
			} else {
				zones = append(zones, zone)
			}
		}
	}
	logger.Info("Loaded zones from Redis: ", zones)
	autodns.LastZoneUpdate = time.Now()
	autodns.Zones = zones
}

func (autodns *Autodns) A(name string, z *Zone, record *Record) (answers, extras []dns.RR) {
	for _, a := range record.A {
		if a.Ip == nil {
			continue
		}
		r := new(dns.A)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA,
			Class: dns.ClassINET, Ttl: autodns.minTtl(a.Ttl)}
		r.A = a.Ip
		answers = append(answers, r)
	}
	return
}

func (autodns *Autodns) AAAA(name string, z *Zone, record *Record) (answers, extras []dns.RR) {
	for _, aaaa := range record.AAAA {
		if aaaa.Ip == nil {
			continue
		}
		r := new(dns.AAAA)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeAAAA,
			Class: dns.ClassINET, Ttl: autodns.minTtl(aaaa.Ttl)}
		r.AAAA = aaaa.Ip
		answers = append(answers, r)
	}
	return
}

func (autodns *Autodns) CNAME(name string, z *Zone, record *Record) (answers, extras []dns.RR) {
	for _, cname := range record.CNAME {
		if len(cname.Host) == 0 {
			continue
		}
		r := new(dns.CNAME)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME,
			Class: dns.ClassINET, Ttl: autodns.minTtl(cname.Ttl)}
		r.Target = dns.Fqdn(cname.Host)
		answers = append(answers, r)
	}
	return
}

func (autodns *Autodns) NS(name string, z *Zone, record *Record) (answers, extras []dns.RR) {
	for _, ns := range record.NS {
		if len(ns.Host) == 0 {
			continue
		}
		r := new(dns.NS)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeNS,
			Class: dns.ClassINET, Ttl: autodns.minTtl(ns.Ttl)}
		r.Ns = ns.Host
		answers = append(answers, r)
		extras = append(extras, autodns.hosts(ns.Host, z)...)
	}
	return
}

func (autodns *Autodns) MX(name string, z *Zone, record *Record) (answers, extras []dns.RR) {
	for _, mx := range record.MX {
		if len(mx.Host) == 0 {
			continue
		}
		r := new(dns.MX)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeMX,
			Class: dns.ClassINET, Ttl: autodns.minTtl(mx.Ttl)}
		r.Mx = mx.Host
		r.Preference = mx.Preference
		answers = append(answers, r)
		extras = append(extras, autodns.hosts(mx.Host, z)...)
	}
	return
}

func (autodns *Autodns) SRV(name string, z *Zone, record *Record) (answers, extras []dns.RR) {
	for _, srv := range record.SRV {
		if len(srv.Target) == 0 {
			continue
		}
		r := new(dns.SRV)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeSRV,
			Class: dns.ClassINET, Ttl: autodns.minTtl(srv.Ttl)}
		r.Target = srv.Target
		r.Weight = srv.Weight
		r.Port = srv.Port
		r.Priority = srv.Priority
		answers = append(answers, r)
		extras = append(extras, autodns.hosts(srv.Target, z)...)
	}
	return
}

func (autodns *Autodns) SOA(name string, z *Zone, record *Record) (answers, extras []dns.RR) {
	r := new(dns.SOA)
	if record.SOA.Ns == "" {
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeSOA,
			Class: dns.ClassINET, Ttl: autodns.Ttl}
		r.Ns = "ns1." + name
		r.Mbox = "hostmaster." + name
		r.Refresh = 86400
		r.Retry = 7200
		r.Expire = 3600
		r.Minttl = autodns.Ttl
	} else {
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(z.Name), Rrtype: dns.TypeSOA,
			Class: dns.ClassINET, Ttl: autodns.minTtl(record.SOA.Ttl)}
		r.Ns = record.SOA.Ns
		r.Mbox = record.SOA.MBox
		r.Refresh = record.SOA.Refresh
		r.Retry = record.SOA.Retry
		r.Expire = record.SOA.Expire
		r.Minttl = record.SOA.MinTtl
	}
	r.Serial = autodns.serial()
	answers = append(answers, r)
	return
}

func (autodns *Autodns) CAA(name string, z *Zone, record *Record) (answers, extras []dns.RR) {
	if record == nil {
		return
	}
	for _, caa := range record.CAA {
		if caa.Value == "" || caa.Tag == "" {
			continue
		}
		r := new(dns.CAA)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCAA, Class: dns.ClassINET}
		r.Flag = caa.Flag
		r.Tag = caa.Tag
		r.Value = caa.Value
		answers = append(answers, r)
	}
	return
}

func (autodns *Autodns) AXFR(z *Zone) (records []dns.RR) {
	//soa, _ := redis.SOA(z.Name, z, record)
	soa := make([]dns.RR, 0)
	answers := make([]dns.RR, 0, 10)
	extras := make([]dns.RR, 0, 10)

	// Allocate slices for rr Records
	records = append(records, soa...)
	for key := range z.Locations {
		if key == "@" {
			location := autodns.findLocation(z.Name, z)
			record := autodns.get(location, z)
			soa, _ = autodns.SOA(z.Name, z, record)
		} else {
			fqdnKey := dns.Fqdn(key) + z.Name
			var as []dns.RR
			var xs []dns.RR

			location := autodns.findLocation(fqdnKey, z)
			record := autodns.get(location, z)

			// Pull all zone records
			as, xs = autodns.A(fqdnKey, z, record)
			answers = append(answers, as...)
			extras = append(extras, xs...)

			as, xs = autodns.AAAA(fqdnKey, z, record)
			answers = append(answers, as...)
			extras = append(extras, xs...)

			as, xs = autodns.CNAME(fqdnKey, z, record)
			answers = append(answers, as...)
			extras = append(extras, xs...)

			as, xs = autodns.MX(fqdnKey, z, record)
			answers = append(answers, as...)
			extras = append(extras, xs...)

			as, xs = autodns.SRV(fqdnKey, z, record)
			answers = append(answers, as...)
			extras = append(extras, xs...)

			as, xs = autodns.TXT(fqdnKey, z, record)
			answers = append(answers, as...)
			extras = append(extras, xs...)
		}
	}

	records = soa
	records = append(records, answers...)
	records = append(records, extras...)
	records = append(records, soa...)

	fmt.Println(records)
	return
}

func (autodns *Autodns) hosts(name string, z *Zone) []dns.RR {
	var (
		record  *Record
		answers []dns.RR
	)
	location := autodns.findLocation(name, z)
	if location == "" {
		return nil
	}
	record = autodns.get(location, z)
	a, _ := autodns.A(name, z, record)
	answers = append(answers, a...)
	aaaa, _ := autodns.AAAA(name, z, record)
	answers = append(answers, aaaa...)
	cname, _ := autodns.CNAME(name, z, record)
	answers = append(answers, cname...)
	return answers
}

func (autodns *Autodns) serial() uint32 {
	return uint32(time.Now().Unix())
}

func (autodns *Autodns) minTtl(ttl uint32) uint32 {
	if autodns.Ttl == 0 && ttl == 0 {
		return defaultTtl
	}
	if autodns.Ttl == 0 {
		return ttl
	}
	if ttl == 0 {
		return autodns.Ttl
	}
	if autodns.Ttl < ttl {
		return autodns.Ttl
	}
	return ttl
}

func (autodns *Autodns) findLocation(query string, z *Zone) string {
	var (
		ok                                 bool
		closestEncloser, sourceOfSynthesis string
	)

	// request for zone records
	if query == z.Name {
		return query
	}

	query = strings.TrimSuffix(query, "."+z.Name)

	if _, ok = z.Locations[query]; ok {
		return query
	}

	closestEncloser, sourceOfSynthesis, ok = splitQuery(query)
	for ok {
		ceExists := keyMatches(closestEncloser, z) || keyExists(closestEncloser, z)
		ssExists := keyExists(sourceOfSynthesis, z)
		if ceExists {
			if ssExists {
				return sourceOfSynthesis
			} else {
				return ""
			}
		} else {
			closestEncloser, sourceOfSynthesis, ok = splitQuery(closestEncloser)
		}
	}
	return ""
}

func (autodns *Autodns) get(key string, z *Zone) *Record {
	var (
		err   error
		reply interface{}
		val   string
	)
	conn := autodns.Pool.Get()
	if conn == nil {
		fmt.Println("error connecting to redis")
		return nil
	}
	defer conn.Close()

	var label string
	if key == z.Name {
		label = "@"
	} else {
		label = key
	}

	reply, err = conn.Do("HGET", autodns.keyPrefix+z.Name+autodns.keySuffix, label)
	if err != nil {
		return nil
	}
	val, err = redisCon.String(reply, nil)
	if err != nil {
		return nil
	}
	r := new(Record)
	err = json.Unmarshal([]byte(val), r)
	if err != nil {
		fmt.Println("parse error : ", val, err)
		return nil
	}
	return r
}

func keyExists(key string, z *Zone) bool {
	_, ok := z.Locations[key]
	return ok
}

func keyMatches(key string, z *Zone) bool {
	for value := range z.Locations {
		if strings.HasSuffix(value, key) {
			return true
		}
	}
	return false
}

func splitQuery(query string) (string, string, bool) {
	if query == "" {
		return "", "", false
	}
	var (
		splits            []string
		closestEncloser   string
		sourceOfSynthesis string
	)
	splits = strings.SplitAfterN(query, ".", 2)
	if len(splits) == 2 {
		closestEncloser = splits[1]
		sourceOfSynthesis = "*." + closestEncloser
	} else {
		closestEncloser = ""
		sourceOfSynthesis = "*"
	}
	return closestEncloser, sourceOfSynthesis, true
}

func (autodns *Autodns) Connect() {
	autodns.Pool = &redisCon.Pool{
		Dial: func() (redisCon.Conn, error) {
			opts := []redisCon.DialOption{}
			if autodns.redisPassword != "" {
				opts = append(opts, redisCon.DialPassword(autodns.redisPassword))
			}
			if autodns.connectTimeout != 0 {
				opts = append(opts, redisCon.DialConnectTimeout(time.Duration(autodns.connectTimeout)*time.Millisecond))
			}
			if autodns.readTimeout != 0 {
				opts = append(opts, redisCon.DialReadTimeout(time.Duration(autodns.readTimeout)*time.Millisecond))
			}

			return redisCon.Dial("tcp", autodns.redisAddress, opts...)
		},
	}
}

func (autodns *Autodns) save(zone string, subdomain string, value string) error {
	var err error

	conn := autodns.Pool.Get()
	if conn == nil {
		fmt.Println("error connecting to redis")
		return nil
	}
	defer conn.Close()

	_, err = conn.Do("HSET", autodns.keyPrefix+zone+autodns.keySuffix, subdomain, value)
	return err
}

func (autodns *Autodns) load(zone string) *Zone {
	var (
		reply interface{}
		err   error
		vals  []string
	)

	conn := autodns.Pool.Get()
	if conn == nil {
		fmt.Println("error connecting to redis")
		return nil
	}
	defer conn.Close()

	reply, err = conn.Do("HKEYS", autodns.keyPrefix+zone+autodns.keySuffix)
	if err != nil {
		return nil
	}
	z := new(Zone)
	z.Name = zone
	vals, err = redisCon.Strings(reply, nil)
	if err != nil {
		return nil
	}
	z.Locations = make(map[string]struct{})
	for _, val := range vals {
		z.Locations[val] = struct{}{}
	}

	return z
}

func split255(s string) []string {
	if len(s) < 255 {
		return []string{s}
	}
	sx := []string{}
	p, i := 0, 255
	for {
		if i <= len(s) {
			sx = append(sx, s[p:i])
		} else {
			sx = append(sx, s[p:])
			break

		}
		p, i = p+255, i+255
	}

	return sx
}

const (
	defaultTtl     = 360
	hostmaster     = "hostmaster"
	zoneUpdateTime = 10 * time.Minute
	transferLength = 1000
)

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
