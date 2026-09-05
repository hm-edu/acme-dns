package nameserver

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"github.com/hm-edu/acme-dns/pkg/acmedns"
	log "github.com/sirupsen/logrus"
)

// ednsUDPSize is the EDNS0 UDP payload size advertised in responses to EDNS0 queries.
// 1232 bytes is the value recommended by DNS flag day 2020 and fits within the
// server's receive buffer (dns.DefaultMsgSize).
const ednsUDPSize = 1232

// Records is a slice of ResourceRecords
type Records struct {
	Records []dns.RR
}

// DNSServer is the main struct for acme-dns DNS server
type DNSServer struct {
	DB      acmedns.Database
	Domain  string
	Server  *dns.Server
	SOA     dns.RR
	Domains map[string]Records

	// personalKeyAuth holds the TXT value served for the server's own
	// _acme-challenge record. It is written by the ACME challenge provider and
	// read by the DNS handler goroutines, hence the atomic access.
	personalKeyAuth atomic.Value
}

// SetPersonalKeyAuth sets the TXT value served for the server's own _acme-challenge record
func (d *DNSServer) SetPersonalKeyAuth(token string) {
	d.personalKeyAuth.Store(token)
}

// PersonalKeyAuth returns the TXT value served for the server's own _acme-challenge record
func (d *DNSServer) PersonalKeyAuth() string {
	v, _ := d.personalKeyAuth.Load().(string)
	return v
}

// New creates and returns a new DNSServer
func New(db acmedns.Database, addr string, proto string, domain string) *DNSServer {
	server := &DNSServer{}
	server.Server = &dns.Server{Addr: addr, Net: proto}
	server.Server.Handler = dns.HandlerFunc(server.handleRequest)
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	server.Domain = strings.ToLower(domain)
	server.DB = db
	server.SetPersonalKeyAuth("")
	server.Domains = make(map[string]Records)
	return server
}

// Start starts the DNSServer
func (d *DNSServer) Start(errorChannel chan error) {
	log.WithFields(log.Fields{"addr": d.Server.Addr, "proto": d.Server.Net}).Info("Listening DNS")
	err := d.Server.ListenAndServe()
	if err != nil {
		errorChannel <- err
	}
}

// ParseRecords parses a slice of DNS record strings from the config
func (d *DNSServer) ParseRecords(config acmedns.DNSConfig) {
	for _, v := range config.General.StaticRecords {
		rr, err := dns.New(strings.ToLower(v))
		if err != nil || rr == nil {
			errstr := "empty record"
			if err != nil {
				errstr = err.Error()
			}
			log.WithFields(log.Fields{"error": errstr, "rr": v}).Warning("Could not parse RR from config")
			continue
		}
		d.appendRR(rr)
	}
	serial := time.Now().Format("2006010215")
	SOAstring := fmt.Sprintf("%s. SOA %s. %s. %s 28800 7200 604800 86400",
		strings.ToLower(config.General.Domain),
		strings.ToLower(config.General.Nsname),
		strings.ToLower(config.General.Nsadmin),
		serial)
	soarr, err := dns.New(SOAstring)
	if err != nil || soarr == nil {
		errstr := "empty record"
		if err != nil {
			errstr = err.Error()
		}
		log.WithFields(log.Fields{"error": errstr, "soa": SOAstring}).Error("Error while adding SOA record")
	} else {
		d.appendRR(soarr)
		d.SOA = soarr
	}
}

func (d *DNSServer) appendRR(rr dns.RR) {
	addDomain := rr.Header().Name
	_, ok := d.Domains[addDomain]
	if !ok {
		d.Domains[addDomain] = Records{[]dns.RR{rr}}
	} else {
		drecs := d.Domains[addDomain]
		drecs.Records = append(drecs.Records, rr)
		d.Domains[addDomain] = drecs
	}
	log.WithFields(log.Fields{"recordtype": dnsutil.TypeToString(dns.RRToType(rr)), "domain": addDomain}).Debug("Adding new record to domain")
}

func (d *DNSServer) handleRequest(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
	// The server only decodes the header and question section before invoking the
	// handler, decode the rest so EDNS0 information becomes available.
	if err := r.Unpack(); err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Debug("Could not unpack DNS message")
		return
	}
	m := new(dns.Msg)
	dnsutil.SetReply(m, r)

	// r.UDPSize is only set when the request carried an EDNS0 OPT record.
	hasEDNS := r.UDPSize > 0
	if hasEDNS {
		// RFC 6891: a response to an EDNS0 query must carry an OPT record.
		m.UDPSize = ednsUDPSize
	}
	if hasEDNS && r.Version != 0 {
		m.Rcode = dns.RcodeBadVers
	} else if r.Opcode == dns.OpcodeQuery {
		d.readQuery(m)
	}
	if _, err := io.Copy(w, m); err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Debug("Could not write DNS response")
	}
}

func (d *DNSServer) readQuery(m *dns.Msg) {
	var authoritative = false
	for _, que := range m.Question {
		if rr, rc, auth, err := d.answer(que); err == nil {
			if auth {
				authoritative = auth
			}
			m.Rcode = rc
			m.Answer = append(m.Answer, rr...)
		}
	}
	m.Authoritative = authoritative
	if authoritative && m.Rcode == dns.RcodeNameError && d.SOA != nil {
		m.Ns = append(m.Ns, d.SOA)
	}
}

func (d *DNSServer) getRecord(q dns.RR) ([]dns.RR, error) {
	var rr []dns.RR
	var cnames []dns.RR
	qname := q.Header().Name
	qtype := dns.RRToType(q)
	domain, ok := d.Domains[strings.ToLower(qname)]
	if !ok {
		return rr, fmt.Errorf("no records for domain %s", qname)
	}
	for _, ri := range domain.Records {
		rtype := dns.RRToType(ri)
		if rtype == qtype {
			rr = append(rr, ri)
		}
		if rtype == dns.TypeCNAME {
			cnames = append(cnames, ri)
		}
	}
	if len(rr) == 0 {
		return cnames, nil
	}
	return rr, nil
}

func (d *DNSServer) answeringForDomain(name string) bool {
	if d.Domain == strings.ToLower(name) {
		return true
	}
	_, ok := d.Domains[strings.ToLower(name)]
	return ok
}

func (d *DNSServer) isAuthoritative(name string) bool {
	if d.answeringForDomain(name) {
		return true
	}
	domainParts := strings.Split(strings.ToLower(name), ".")
	for i := range domainParts {
		if d.answeringForDomain(strings.Join(domainParts[i:], ".")) {
			return true
		}
	}
	return false
}

func (d *DNSServer) isOwnChallenge(name string) bool {
	domainParts := strings.SplitN(name, ".", 2)
	if len(domainParts) == 2 {
		if strings.ToLower(domainParts[0]) == "_acme-challenge" {
			domain := strings.ToLower(domainParts[1])
			if !strings.HasSuffix(domain, ".") {
				domain = domain + "."
			}
			if domain == d.Domain {
				return true
			}
		}
	}
	return false
}

func (d *DNSServer) answer(q dns.RR) ([]dns.RR, uint16, bool, error) {
	var rcode uint16
	var err error
	var txtRRs []dns.RR
	qname := q.Header().Name
	qtype := dns.RRToType(q)
	var authoritative = d.isAuthoritative(qname)
	if !d.isOwnChallenge(qname) && !d.answeringForDomain(qname) {
		rcode = dns.RcodeNameError
	}
	r, _ := d.getRecord(q)
	if qtype == dns.TypeTXT {
		if d.isOwnChallenge(qname) {
			txtRRs, err = d.answerOwnChallenge(q)
		} else {
			txtRRs, err = d.answerTXT(q)
		}
		if err == nil {
			r = append(r, txtRRs...)
		}
	}
	if len(r) > 0 {
		rcode = dns.RcodeSuccess
	}
	log.WithFields(log.Fields{"qtype": dnsutil.TypeToString(qtype), "domain": qname, "rcode": dnsutil.RcodeToString(rcode)}).Debug("Answering question for domain")
	return r, rcode, authoritative, nil
}

func (d *DNSServer) answerTXT(q dns.RR) ([]dns.RR, error) {
	var ra []dns.RR
	subdomain := acmedns.SanitizeDomainQuestion(q.Header().Name)
	atxt, err := d.DB.GetTXTForDomain(subdomain)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Debug("Error while trying to get record")
		return ra, err
	}
	for _, v := range atxt {
		if len(v) > 0 {
			ra = append(ra, newTXT(q.Header().Name, v))
		}
	}
	return ra, nil
}

func (d *DNSServer) answerOwnChallenge(q dns.RR) ([]dns.RR, error) {
	return []dns.RR{newTXT(q.Header().Name, d.PersonalKeyAuth())}, nil
}

func newTXT(name string, value string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 1},
		TXT: rdata.TXT{Txt: []string{value}},
	}
}
