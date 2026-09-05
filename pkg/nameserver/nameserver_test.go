package nameserver

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	testdb "github.com/erikstmartin/go-testdb"
	"github.com/hm-edu/acme-dns/pkg/acmedns"
	"github.com/hm-edu/acme-dns/pkg/database"
	log "github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
)

var loghook = new(logrustest.Hook)
var testDNSServer *DNSServer
var testDB acmedns.Database

var records = []string{
	"auth.example.org. A 192.168.1.100",
	"ns1.auth.example.org. A 192.168.1.101",
	"cn.example.org CNAME something.example.org.",
	"!''b', unparseable ",
	"ns2.auth.example.org. A 192.168.1.102",
}

var testConfig = acmedns.DNSConfig{
	General: acmedns.GeneralConfig{
		Domain:        "auth.example.org",
		Listen:        "127.0.0.1:15353",
		Proto:         "udp",
		Nsname:        "ns1.auth.example.org",
		Nsadmin:       "admin.example.org",
		StaticRecords: records,
		Debug:         false,
	},
}

func setupTestLogger() {
	log.SetOutput(io.Discard)
	log.AddHook(loghook)
}

func loggerHasEntryWithMessage(message string) bool {
	for _, v := range loghook.Entries {
		if v.Message == message {
			return true
		}
	}
	return false
}

func TestMain(m *testing.M) {
	setupTestLogger()

	newDb := database.New()
	_ = newDb.Init("sqlite3", ":memory:")
	testDB = newDb

	testDNSServer = New(testDB, testConfig.General.Listen, testConfig.General.Proto, testConfig.General.Domain)
	testDNSServer.ParseRecords(testConfig)

	var wg sync.WaitGroup
	wg.Add(1)
	testDNSServer.Server.NotifyStartedFunc = func(context.Context) {
		wg.Done()
	}
	go testDNSServer.Start(make(chan error, 1))
	wg.Wait()

	exitval := m.Run()
	testDNSServer.Server.Shutdown(context.Background())
	testDB.Close()
	os.Exit(exitval)
}

type resolver struct {
	server string
}

func (r *resolver) lookup(host string, qtype uint16) (*dns.Msg, error) {
	msg := dns.NewMsg(host, qtype)
	msg.ID = dns.ID()
	in, err := dns.Exchange(context.Background(), msg, "udp", r.server)
	if err != nil {
		return in, fmt.Errorf("Error querying the server [%v]", err)
	}
	if in != nil && in.Rcode != dns.RcodeSuccess {
		return in, fmt.Errorf("Received error from the server [%s]", dnsutil.RcodeToString(in.Rcode))
	}
	return in, nil
}

func hasExpectedTXTAnswer(answer []dns.RR, cmpTXT string) error {
	for _, record := range answer {
		if rec, ok := record.(*dns.TXT); ok {
			for _, txtValue := range rec.Txt {
				if txtValue == cmpTXT {
					return nil
				}
			}
		} else {
			errmsg := fmt.Sprintf("Got answer of unexpected type [%q]", answer[0])
			return errors.New(errmsg)
		}
	}
	return errors.New("Expected answer not found")
}

func TestQuestionDBError(t *testing.T) {
	testdb.SetQueryWithArgsFunc(func(query string, args []driver.Value) (result driver.Rows, err error) {
		columns := []string{"Username", "Password", "Subdomain", "Value", "LastActive"}
		return testdb.RowsFromSlice(columns, [][]driver.Value{}), errors.New("Prepared query error")
	})

	defer testdb.Reset()

	tdb, err := sql.Open("testdb", "")
	if err != nil {
		t.Errorf("Got error: %v", err)
	}
	oldDb := testDB.GetBackend()

	testDB.SetBackend(tdb)
	defer testDB.SetBackend(oldDb)

	q := &dns.TXT{Hdr: dns.Header{Name: dnsutil.Fqdn("whatever.tld"), Class: dns.ClassINET}}
	_, err = testDNSServer.answerTXT(q)
	if err == nil {
		t.Errorf("Expected error but got none")
	}
}

func TestParse(t *testing.T) {
	var testcfg = acmedns.DNSConfig{
		General: acmedns.GeneralConfig{
			Domain:        ")",
			Nsname:        "ns1.auth.example.org",
			Nsadmin:       "admin.example.org",
			StaticRecords: []string{},
			Debug:         false,
		},
	}
	testDNSServer.ParseRecords(testcfg)
	if !loggerHasEntryWithMessage("Error while adding SOA record") {
		t.Errorf("Expected SOA parsing to return error, but did not find one")
	}
	if !loggerHasEntryWithMessage("Could not parse RR from config") {
		t.Errorf("Expected unparseable static record to be logged, but did not find one")
	}
}

func TestResolveA(t *testing.T) {
	resolv := resolver{server: "127.0.0.1:15353"}
	answer, err := resolv.lookup("auth.example.org", dns.TypeA)
	if err != nil {
		t.Errorf("%v", err)
	}

	if len(answer.Answer) == 0 {
		t.Error("No answer for DNS query")
	}

	_, err = resolv.lookup("nonexistent.domain.tld", dns.TypeA)
	if err == nil {
		t.Errorf("Was expecting error because of NXDOMAIN but got none")
	}
}

func TestEDNS(t *testing.T) {
	resolv := resolver{server: "127.0.0.1:15353"}
	answer, _ := resolv.lookup("auth.example.org", dns.TypeOPT)
	if answer.Rcode != dns.RcodeSuccess {
		t.Errorf("Was expecing NOERROR rcode for OPT query, but got [%s] instead.", dnsutil.RcodeToString(answer.Rcode))
	}
}

func TestEDNSA(t *testing.T) {
	msg := dns.NewMsg("auth.example.org", dns.TypeA)
	msg.ID = dns.ID()
	msg.UDPSize = 512
	msg.Security = true
	in, err := dns.Exchange(context.Background(), msg, "udp", "127.0.0.1:15353")
	if err != nil {
		t.Fatalf("Error querying the server [%v]", err)
	}
	if in.Rcode != dns.RcodeSuccess {
		t.Errorf("Received error from the server [%s]", dnsutil.RcodeToString(in.Rcode))
	}
	if in.UDPSize == 0 {
		t.Errorf("Should have got OPT back")
	}
}

func TestEDNSBADVERS(t *testing.T) {
	msg := dns.NewMsg("auth.example.org", dns.TypeA)
	msg.ID = dns.ID()
	// Pack does not honour msg.Version, so add a raw OPT RR with version 1 to the additional section.
	o := &dns.OPT{Hdr: dns.Header{Name: "."}}
	o.SetVersion(1)
	msg.Extra = append(msg.Extra, o)
	in, err := dns.Exchange(context.Background(), msg, "udp", "127.0.0.1:15353")
	if err != nil {
		t.Fatalf("Error querying the server [%v]", err)
	}
	if in.Rcode != dns.RcodeBadVers {
		t.Errorf("Received unexpected rcode from the server [%s]", dnsutil.RcodeToString(in.Rcode))
	}
}

func TestResolveCNAME(t *testing.T) {
	resolv := resolver{server: "127.0.0.1:15353"}
	expected := "cn.example.org.	3600	IN	CNAME	something.example.org."
	answer, err := resolv.lookup("cn.example.org", dns.TypeCNAME)
	if err != nil {
		t.Errorf("Got unexpected error: %s", err)
	}
	if len(answer.Answer) != 1 {
		t.Fatalf("Expected exactly 1 RR in answer, but got %d instead.", len(answer.Answer))
	}
	if dns.RRToType(answer.Answer[0]) != dns.TypeCNAME {
		t.Errorf("Expected a CNAME answer, but got [%s] instead.", dnsutil.TypeToString(dns.RRToType(answer.Answer[0])))
	}
	if answer.Answer[0].String() != expected {
		t.Errorf("Expected CNAME answer [%s] but got [%s] instead.", expected, answer.Answer[0].String())
	}
}

func TestAuthoritative(t *testing.T) {
	resolv := resolver{server: "127.0.0.1:15353"}
	answer, _ := resolv.lookup("nonexistent.auth.example.org", dns.TypeA)
	if answer.Rcode != dns.RcodeNameError {
		t.Errorf("Was expecing NXDOMAIN rcode, but got [%s] instead.", dnsutil.RcodeToString(answer.Rcode))
	}
	if len(answer.Ns) != 1 {
		t.Fatalf("Was expecting exactly one answer (SOA) for invalid subdomain, but got %d", len(answer.Ns))
	}
	if dns.RRToType(answer.Ns[0]) != dns.TypeSOA {
		t.Errorf("Was expecting SOA record as answer for NXDOMAIN but got [%s]", dnsutil.TypeToString(dns.RRToType(answer.Ns[0])))
	}
	if !answer.Authoritative {
		t.Errorf("Was expecting authoritative bit to be set")
	}
	nanswer, _ := resolv.lookup("nonexsitent.nonauth.tld", dns.TypeA)
	if len(nanswer.Answer) > 0 {
		t.Errorf("Didn't expect answers for non authotitative domain query")
	}
	if nanswer.Authoritative {
		t.Errorf("Authoritative bit should not be set for non-authoritative domain.")
	}
}

func TestResolveTXT(t *testing.T) {
	resolv := resolver{server: "127.0.0.1:15353"}
	validTXT := "______________valid_response_______________"

	atxt, err := testDB.Register(acmedns.CIDRSlice{})
	if err != nil {
		t.Errorf("Could not initiate db record: [%v]", err)
		return
	}
	atxt.Value = validTXT
	err = testDB.Update(atxt.ACMETxtPost)
	if err != nil {
		t.Errorf("Could not update db record: [%v]", err)
		return
	}

	for i, test := range []struct {
		subDomain   string
		expTXT      string
		getAnswer   bool
		validAnswer bool
	}{
		{atxt.Subdomain, validTXT, true, true},
		{atxt.Subdomain, "invalid", true, false},
		{"a097455b-52cc-4569-90c8-7a4b97c6eba8", validTXT, false, false},
	} {
		answer, err := resolv.lookup(test.subDomain+".auth.example.org", dns.TypeTXT)
		if err != nil {
			if test.getAnswer {
				t.Fatalf("Test %d: Expected answer but got: %v", i, err)
			}
		} else {
			if !test.getAnswer {
				t.Errorf("Test %d: Expected no answer, but got one.", i)
			}
		}

		if len(answer.Answer) > 0 {
			if !test.getAnswer && dns.RRToType(answer.Answer[0]) != dns.TypeSOA {
				t.Errorf("Test %d: Expected no answer, but got: [%q]", i, answer)
			}
			if test.getAnswer {
				err = hasExpectedTXTAnswer(answer.Answer, test.expTXT)
				if err != nil {
					if test.validAnswer {
						t.Errorf("Test %d: %v", i, err)
					}
				} else {
					if !test.validAnswer {
						t.Errorf("Test %d: Answer was not expected to be valid, answer [%q], compared to [%s]", i, answer, test.expTXT)
					}
				}
			}
		} else {
			if test.getAnswer {
				t.Errorf("Test %d: Expected answer, but didn't get one", i)
			}
		}
	}
}

func TestOwnChallenge(t *testing.T) {
	resolv := resolver{server: "127.0.0.1:15353"}
	testDNSServer.SetPersonalKeyAuth("own-challenge-token")
	defer testDNSServer.SetPersonalKeyAuth("")

	answer, err := resolv.lookup("_acme-challenge.auth.example.org", dns.TypeTXT)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
	if err := hasExpectedTXTAnswer(answer.Answer, "own-challenge-token"); err != nil {
		t.Errorf("Expected own challenge token in answer: %v", err)
	}
}

func TestCaseInsensitiveResolveA(t *testing.T) {
	resolv := resolver{server: "127.0.0.1:15353"}
	answer, err := resolv.lookup("aUtH.eXAmpLe.org", dns.TypeA)
	if err != nil {
		t.Errorf("%v", err)
	}

	if len(answer.Answer) == 0 {
		t.Error("No answer for DNS query")
	}
}

func TestCaseInsensitiveResolveSOA(t *testing.T) {
	resolv := resolver{server: "127.0.0.1:15353"}
	answer, _ := resolv.lookup("doesnotexist.aUtH.eXAmpLe.org", dns.TypeSOA)
	if answer.Rcode != dns.RcodeNameError {
		t.Errorf("Was expecing NXDOMAIN rcode, but got [%s] instead.", dnsutil.RcodeToString(answer.Rcode))
	}

	if len(answer.Ns) == 0 {
		t.Error("No SOA answer for DNS query")
	}
}
