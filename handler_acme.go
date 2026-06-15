package autodns

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
	"unicode"

	"github.com/coredns/coredns/request"
	"github.com/gomodule/redigo/redis"
	"github.com/miekg/dns"
)

const (
	acmeRegPrefix = "_acme-reg."
	acmeDelPrefix = "_acme-del."
)

func validAcmeDigest(digest string) bool {
	if len(digest) == 0 || len(digest) > 63 {
		return false
	}
	for _, r := range digest {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func parseAcmeRegQuery(qname, zone string) (digest, hostLabel string, ok bool) {
	if len(qname) < len(acmeRegPrefix) || !strings.EqualFold(qname[:len(acmeRegPrefix)], acmeRegPrefix) {
		return "", "", false
	}
	rest := qname[len(acmeRegPrefix):]
	zoneSuffix := "." + zone
	if len(rest) < len(zoneSuffix) || !strings.EqualFold(rest[len(rest)-len(zoneSuffix):], zoneSuffix) {
		return "", "", false
	}
	rest = rest[:len(rest)-len(zoneSuffix)]
	if rest == "" {
		return "", "", false
	}
	parts := strings.SplitN(rest, ".", 2)
	digest = parts[0]
	if !validAcmeDigest(digest) {
		return "", "", false
	}
	if len(parts) == 2 {
		hostLabel = strings.ToLower(parts[1])
	}
	return digest, hostLabel, true
}

func parseAcmeDelQuery(qname, zone string) (digest, hostLabel string, ok bool) {
	if len(qname) < len(acmeDelPrefix) || !strings.EqualFold(qname[:len(acmeDelPrefix)], acmeDelPrefix) {
		return "", "", false
	}
	rest := qname[len(acmeDelPrefix):]
	zoneSuffix := "." + zone
	if len(rest) < len(zoneSuffix) || !strings.EqualFold(rest[len(rest)-len(zoneSuffix):], zoneSuffix) {
		return "", "", false
	}
	rest = rest[:len(rest)-len(zoneSuffix)]
	if rest == "" {
		return "", "", true
	}
	parts := strings.SplitN(rest, ".", 2)
	if len(parts) == 2 {
		if !validAcmeDigest(parts[0]) {
			return "", "", false
		}
		return parts[0], strings.ToLower(parts[1]), true
	}
	label := parts[0]
	if acmeDelLabelLooksLikeDigest(label) {
		return label, "", true
	}
	return "", strings.ToLower(label), true
}

func acmeDelLabelLooksLikeDigest(label string) bool {
	return validAcmeDigest(label) && len(label) >= 16
}

func acmeRedisField(hostLabel string) string {
	if hostLabel == "" {
		return "_acme-challenge"
	}
	return "_acme-challenge." + hostLabel
}

func acmePublicName(zone, hostLabel string) string {
	if hostLabel == "" {
		return "_acme-challenge." + zone
	}
	return "_acme-challenge." + hostLabel + "." + zone
}

func appendAcmeTXT(txts []TXT_Record, digest string, ttl uint32, rotate int) []TXT_Record {
	if rotate <= 0 {
		rotate = defaultAcmeRotate
	}
	out := make([]TXT_Record, 0, len(txts)+1)
	for _, t := range txts {
		if t.Text != digest {
			out = append(out, t)
		}
	}
	out = append(out, TXT_Record{Text: digest, Ttl: ttl})
	if len(out) > rotate {
		out = out[len(out)-rotate:]
	}
	return out
}

func removeAcmeTXT(txts []TXT_Record, digest string) []TXT_Record {
	out := make([]TXT_Record, 0, len(txts))
	for _, t := range txts {
		if t.Text != digest {
			out = append(out, t)
		}
	}
	return out
}

func (autodns *Autodns) readRecordField(zone, field string) (*Record, error) {
	conn := autodns.Pool.Get()
	if conn == nil {
		return nil, errors.New("error connecting to redis")
	}
	defer conn.Close()

	reply, err := conn.Do("HGET", autodns.keyPrefix+zone+autodns.keySuffix, field)
	if err != nil {
		return nil, err
	}
	if reply == nil {
		return &Record{}, nil
	}
	val, err := redis.String(reply, nil)
	if err != nil {
		return nil, err
	}
	record := new(Record)
	if err := json.Unmarshal([]byte(val), record); err != nil {
		return nil, err
	}
	return record, nil
}

func (autodns *Autodns) writeRecordField(zone, field string, record *Record) error {
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return autodns.addRecord(zone, field, string(payload))
}

func (autodns *Autodns) acmeRrTtl() uint32 {
	ttl := autodns.AcmeRrTtl
	if ttl == 0 {
		return defaultAcmeRrTtl
	}
	return ttl
}

func (autodns *Autodns) AddAcmeTXTRecord(zone string, field string, digest string) error {
	record, err := autodns.readRecordField(zone, field)
	if err != nil {
		return err
	}
	record.TXT = appendAcmeTXT(record.TXT, digest, autodns.acmeRrTtl(), autodns.acmeRotate())
	return autodns.writeRecordField(zone, field, record)
}

func (autodns *Autodns) RemoveAcmeTXTDigest(zone string, field string, digest string) error {
	record, err := autodns.readRecordField(zone, field)
	if err != nil {
		return err
	}
	record.TXT = removeAcmeTXT(record.TXT, digest)
	if len(record.TXT) == 0 {
		return autodns.DeleteAcmeTXTRecord(zone, field)
	}
	return autodns.writeRecordField(zone, field, record)
}

func (autodns *Autodns) DeleteAcmeTXTRecord(zone string, field string) error {
	conn := autodns.Pool.Get()
	if conn == nil {
		return errors.New("error connecting to redis")
	}
	defer conn.Close()

	_, err := conn.Do("HDEL", autodns.keyPrefix+zone+autodns.keySuffix, field)
	if err != nil {
		return err
	}
	logger.Info(`Deleted ACME record from redis for `, field)
	return nil
}

func (autodns *Autodns) handleAcmeRegistration(qname, zone, clientIP string, r *dns.Msg, state *request.Request, w dns.ResponseWriter) (int, error) {
	if !IPBelongsToRegisterNetworks(net.ParseIP(clientIP), autodns.acmeNetworks()) {
		logger.Warning(`ACME registration request for `, qname, ` from `, clientIP, ` not in acme networks`)
		return autodns.errorResponse(*state, zone, dns.RcodeNameError, nil)
	}

	digest, hostLabel, ok := parseAcmeRegQuery(qname, zone)
	if !ok {
		return autodns.errorResponse(*state, zone, dns.RcodeNameError, nil)
	}
	if hostLabel != "" && !isAcmeHostLabel(hostLabel) {
		return autodns.errorResponse(*state, zone, dns.RcodeNameError, nil)
	}
	if autodns.acmeHostBelongsToDeny(hostLabel) {
		logger.Warning(`ACME registration for `, qname, ` from `, clientIP, ` denied because of acme.deny setting`)
		return autodns.errorResponse(*state, zone, dns.RcodeNameError, nil)
	}

	field := acmeRedisField(hostLabel)
	logger.Info(`ACME registration for `, acmePublicName(zone, hostLabel), ` digest from `, clientIP)
	if err := autodns.AddAcmeTXTRecord(zone, field, digest); err != nil {
		logger.Error(`Error adding ACME TXT record for `, field, ` error: `, err)
		return autodns.errorResponse(*state, zone, dns.RcodeServerFailure, err)
	}

	reply := acmePublicName(zone, hostLabel)
	if _, err := autodns.TXTReply(qname, []string{strings.TrimSuffix(reply, ".")}, r, state, w); err != nil {
		logger.Error(`Error sending ACME TXT reply for `, qname, ` error: `, err)
		return autodns.errorResponse(*state, zone, dns.RcodeServerFailure, err)
	}
	return dns.RcodeSuccess, nil
}

func (autodns *Autodns) handleAcmeDeletion(qname, zone, clientIP string, r *dns.Msg, state *request.Request, w dns.ResponseWriter) (int, error) {
	if !IPBelongsToRegisterNetworks(net.ParseIP(clientIP), autodns.acmeNetworks()) {
		logger.Warning(`ACME deletion request for `, qname, ` from `, clientIP, ` not in acme networks`)
		return autodns.errorResponse(*state, zone, dns.RcodeNameError, nil)
	}

	digest, hostLabel, ok := parseAcmeDelQuery(qname, zone)
	if !ok {
		return autodns.errorResponse(*state, zone, dns.RcodeNameError, nil)
	}
	if hostLabel != "" && !isAcmeHostLabel(hostLabel) {
		return autodns.errorResponse(*state, zone, dns.RcodeNameError, nil)
	}

	field := acmeRedisField(hostLabel)
	var err error
	if digest != "" {
		logger.Info(`ACME digest removal for `, acmePublicName(zone, hostLabel), ` digest `, digest, ` from `, clientIP)
		err = autodns.RemoveAcmeTXTDigest(zone, field, digest)
	} else {
		logger.Info(`ACME deletion for `, acmePublicName(zone, hostLabel), ` from `, clientIP)
		err = autodns.DeleteAcmeTXTRecord(zone, field)
	}
	if err != nil {
		logger.Error(`Error deleting ACME TXT record for `, field, ` error: `, err)
		return autodns.errorResponse(*state, zone, dns.RcodeServerFailure, err)
	}

	reply := "deleted"
	if hostLabel != "" {
		reply = strings.TrimSuffix(acmePublicName(zone, hostLabel), ".")
	}
	if _, err := autodns.TXTReply(qname, []string{reply}, r, state, w); err != nil {
		return autodns.errorResponse(*state, zone, dns.RcodeServerFailure, err)
	}
	return dns.RcodeSuccess, nil
}

func isAcmeHostLabel(label string) bool {
	if label == "" {
		return false
	}
	for _, part := range strings.Split(label, ".") {
		if part == "" {
			return false
		}
		for _, r := range part {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
				return false
			}
		}
	}
	return true
}
