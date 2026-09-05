package api

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gavv/httpexpect/v2"
	"github.com/hm-edu/acme-dns/pkg/acmedns"
	"github.com/julienschmidt/httprouter"
)

const testAdminKey = "0123456789abcdef0123456789abcdef0123456789abcdef"

func setupAdminRouter(useHeader bool, allowFrom acmedns.CIDRSlice) http.Handler {
	cfg := acmedns.DNSConfig{
		General: acmedns.GeneralConfig{
			Domain: "auth.example.org",
		},
		Database: acmedns.DatabaseSettings{
			Engine:     "sqlite3",
			Connection: ":memory:",
		},
		API: acmedns.APIConfig{
			UseHeader:  useHeader,
			HeaderName: "X-Forwarded-For",
		},
		Admin: acmedns.AdminConfig{
			Enabled:   true,
			APIKey:    testAdminKey,
			AllowFrom: allowFrom,
		},
	}
	a := &API{Config: &cfg, DB: testDB}
	router := httprouter.New()
	router.GET("/admin/domains", a.AdminAuth(a.AdminListDomains))
	router.GET("/admin/domains/:subdomain", a.AdminAuth(a.AdminGetDomain))
	router.GET("/admin/report", a.AdminAuth(a.AdminReport))
	return router
}

func adminExpect(t *testing.T, server *httptest.Server) *httpexpect.Expect {
	return getExpect(t, server).Builder(func(req *httpexpect.Request) {
		req.WithHeader(AdminKeyHeader, testAdminKey)
	})
}

func TestAdminAuthKey(t *testing.T) {
	server := httptest.NewServer(setupAdminRouter(false, acmedns.CIDRSlice{}))
	defer server.Close()
	e := getExpect(t, server)

	e.GET("/admin/domains").Expect().
		Status(http.StatusUnauthorized).
		JSON().Object().HasValue("error", "unauthorized")

	e.GET("/admin/domains").WithHeader(AdminKeyHeader, "wrong-key").Expect().
		Status(http.StatusUnauthorized).
		JSON().Object().HasValue("error", "unauthorized")

	e.GET("/admin/domains").WithHeader(AdminKeyHeader, testAdminKey+"x").Expect().
		Status(http.StatusUnauthorized)

	e.GET("/admin/domains").WithHeader("Authorization", "Basic "+testAdminKey).Expect().
		Status(http.StatusUnauthorized)

	e.GET("/admin/domains").WithHeader(AdminKeyHeader, testAdminKey).Expect().
		Status(http.StatusOK).
		JSON().Object().ContainsKey("domains")

	e.GET("/admin/domains").WithHeader("Authorization", "Bearer "+testAdminKey).Expect().
		Status(http.StatusOK)

	e.GET("/admin/domains").WithHeader("Authorization", "bearer "+testAdminKey).Expect().
		Status(http.StatusOK)

	e.GET("/admin/report").Expect().Status(http.StatusUnauthorized)
	e.GET("/admin/domains/whatever").Expect().Status(http.StatusUnauthorized)
}

func TestAdminAuthEmptyConfiguredKey(t *testing.T) {
	cfg := acmedns.DNSConfig{Admin: acmedns.AdminConfig{Enabled: true}}
	a := &API{Config: &cfg, DB: testDB}
	if a.validAdminKey("") {
		t.Errorf("Empty key must never be valid")
	}
	if a.validAdminKey("anything") {
		t.Errorf("No key configured, nothing must be valid")
	}
}

func TestAdminAuthIPHeader(t *testing.T) {
	server := httptest.NewServer(setupAdminRouter(true, acmedns.CIDRSlice{"192.168.1.0/24", "2001:db8::/32"}))
	defer server.Close()
	e := adminExpect(t, server)

	for _, test := range []struct {
		header string
		status int
	}{
		{"", http.StatusForbidden},
		{"10.0.0.1", http.StatusForbidden},
		{"10.0.0.1, 10.0.0.2", http.StatusForbidden},
		{"192.168.1.42", http.StatusOK},
		{"10.0.0.1, 192.168.1.42", http.StatusOK},
		{"2001:db8:1::1", http.StatusOK},
		{"2001:db9::1", http.StatusForbidden},
		{"not an ip", http.StatusForbidden},
	} {
		e.GET("/admin/report").WithHeader("X-Forwarded-For", test.header).Expect().Status(test.status)
	}

	// Denied by IP must not leak whether the key is valid
	getExpect(t, server).GET("/admin/report").WithHeader("X-Forwarded-For", "10.0.0.1").Expect().
		Status(http.StatusForbidden).
		JSON().Object().HasValue("error", "forbidden")
}

func TestAdminAuthIPRemoteAddr(t *testing.T) {
	allowed := httptest.NewServer(setupAdminRouter(false, acmedns.CIDRSlice{"127.0.0.0/8", "::1/128"}))
	defer allowed.Close()
	adminExpect(t, allowed).GET("/admin/report").Expect().Status(http.StatusOK)

	denied := httptest.NewServer(setupAdminRouter(false, acmedns.CIDRSlice{"10.0.0.0/8"}))
	defer denied.Close()
	adminExpect(t, denied).GET("/admin/report").Expect().Status(http.StatusForbidden)

	// Without header trust a spoofed header must not matter
	adminExpect(t, denied).GET("/admin/report").WithHeader("X-Forwarded-For", "10.1.1.1").Expect().Status(http.StatusForbidden)

	// Empty allowlist permits everyone
	open := httptest.NewServer(setupAdminRouter(false, acmedns.CIDRSlice{}))
	defer open.Close()
	adminExpect(t, open).GET("/admin/report").Expect().Status(http.StatusOK)
}

func TestAdminListDomains(t *testing.T) {
	server := httptest.NewServer(setupAdminRouter(false, acmedns.CIDRSlice{}))
	defer server.Close()
	e := adminExpect(t, server)

	newUser, err := testDB.Register(acmedns.CIDRSlice{"10.1.2.3/32"})
	if err != nil {
		t.Fatalf("Could not create new user, got error [%v]", err)
	}
	// A second registration guarantees at least two domains for the pagination checks
	if _, err := testDB.Register(acmedns.CIDRSlice{}); err != nil {
		t.Fatalf("Could not create second user, got error [%v]", err)
	}
	validTxtData := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	newUser.Value = validTxtData
	if err := testDB.Update(newUser.ACMETxtPost); err != nil {
		t.Fatalf("Could not update record, got error [%v]", err)
	}
	total, _ := testDB.CountDomains()

	resp := e.GET("/admin/domains").WithQuery("limit", AdminMaxLimit+1).Expect().
		Status(http.StatusOK).
		JSON().Object()
	resp.HasValue("total", total)
	resp.HasValue("limit", AdminMaxLimit)
	resp.HasValue("offset", 0)
	domains := resp.Value("domains").Array()
	domains.Length().IsEqual(total)

	var found *httpexpect.Object
	for _, v := range domains.Iter() {
		obj := v.Object()
		if obj.Value("subdomain").String().Raw() == newUser.Subdomain {
			found = obj
		}
	}
	if found == nil {
		t.Fatalf("Registered subdomain %s not found in listing", newUser.Subdomain)
	}
	found.HasValue("username", newUser.Username.String())
	found.HasValue("fulldomain", newUser.Subdomain+".auth.example.org")
	found.HasValue("has_txt", true)
	found.NotContainsKey("password")
	found.Value("allowfrom").Array().ConsistsOf("10.1.2.3/32")
	found.Value("last_update").NotNull()
	records := found.Value("txt_records").Array()
	records.Length().IsEqual(2)
	records.Value(0).Object().HasValue("txt", validTxtData)
	records.Value(0).Object().Value("last_update").NotNull()
	records.Value(1).Object().HasValue("txt", "")
	records.Value(1).Object().Value("last_update").IsNull()

	// Pagination
	page := e.GET("/admin/domains").WithQuery("limit", 1).WithQuery("offset", 1).Expect().
		Status(http.StatusOK).
		JSON().Object()
	page.HasValue("limit", 1)
	page.HasValue("offset", 1)
	page.Value("domains").Array().Length().IsEqual(1)

	for _, test := range []struct {
		limit  string
		offset string
	}{
		{"abc", ""},
		{"0", ""},
		{"-1", ""},
		{"", "abc"},
		{"", "-1"},
	} {
		req := e.GET("/admin/domains")
		if test.limit != "" {
			req = req.WithQuery("limit", test.limit)
		}
		if test.offset != "" {
			req = req.WithQuery("offset", test.offset)
		}
		req.Expect().Status(http.StatusBadRequest).JSON().Object().HasValue("error", "bad_query_parameter")
	}
}

func TestAdminGetDomain(t *testing.T) {
	server := httptest.NewServer(setupAdminRouter(false, acmedns.CIDRSlice{}))
	defer server.Close()
	e := adminExpect(t, server)

	newUser, err := testDB.Register(acmedns.CIDRSlice{})
	if err != nil {
		t.Fatalf("Could not create new user, got error [%v]", err)
	}

	resp := e.GET("/admin/domains/" + newUser.Subdomain).Expect().
		Status(http.StatusOK).
		JSON().Object()
	resp.HasValue("subdomain", newUser.Subdomain)
	resp.HasValue("username", newUser.Username.String())
	resp.HasValue("has_txt", false)
	resp.Value("last_update").IsNull()
	resp.Value("allowfrom").Array().IsEmpty()
	resp.Value("txt_records").Array().Length().IsEqual(2)

	e.GET("/admin/domains/a097455b-52cc-4569-90c8-7a4b97c6eba8").Expect().
		Status(http.StatusNotFound).
		JSON().Object().HasValue("error", "not_found")

	e.GET("/admin/domains/not_a_valid.subdomain").Expect().
		Status(http.StatusBadRequest).
		JSON().Object().HasValue("error", "bad_subdomain")
}

func TestAdminReportEndpoint(t *testing.T) {
	server := httptest.NewServer(setupAdminRouter(false, acmedns.CIDRSlice{}))
	defer server.Close()
	e := adminExpect(t, server)

	newUser, err := testDB.Register(acmedns.CIDRSlice{})
	if err != nil {
		t.Fatalf("Could not create new user, got error [%v]", err)
	}
	newUser.Value = "ccccccccccccccccccccccccccccccccccccccccccc"
	if err := testDB.Update(newUser.ACMETxtPost); err != nil {
		t.Fatalf("Could not update record, got error [%v]", err)
	}
	total, _ := testDB.CountDomains()

	resp := e.GET("/admin/report").Expect().
		Status(http.StatusOK).
		JSON().Object()
	resp.HasValue("domain", "auth.example.org")
	resp.HasValue("database_engine", "sqlite3")
	resp.Value("generated_at").String().NotEmpty()
	counts := resp.Value("domains").Object()
	counts.HasValue("total", total)
	counts.Value("with_txt").Number().Ge(1)
	counts.Value("updated_last_24h").Number().Ge(1)
	counts.Value("never_updated").Number().Ge(0)
	recent := resp.Value("recently_updated").Array()
	recent.Length().Ge(1)
	recent.Value(0).Object().HasValue("subdomain", newUser.Subdomain)
	recent.Value(0).Object().HasValue("fulldomain", newUser.Subdomain+".auth.example.org")
}

func TestAdminDBErrors(t *testing.T) {
	server := httptest.NewServer(setupAdminRouter(false, acmedns.CIDRSlice{}))
	defer server.Close()
	e := adminExpect(t, server)

	oldDb := testDB.GetBackend()
	db, mock, _ := sqlmock.New()
	testDB.SetBackend(db)
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)
	defer testDB.SetBackend(oldDb)

	mock.ExpectQuery("SELECT COUNT").WillReturnError(errors.New("error"))
	e.GET("/admin/domains").Expect().Status(http.StatusInternalServerError).JSON().Object().HasValue("error", "db_error")

	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT r.Username").WillReturnError(errors.New("error"))
	e.GET("/admin/domains").Expect().Status(http.StatusInternalServerError).JSON().Object().HasValue("error", "db_error")

	mock.ExpectQuery("SELECT r.Username").WillReturnError(errors.New("error"))
	e.GET("/admin/domains/a097455b-52cc-4569-90c8-7a4b97c6eba8").Expect().Status(http.StatusInternalServerError).JSON().Object().HasValue("error", "db_error")

	mock.ExpectQuery("SELECT r.Subdomain").WillReturnError(errors.New("error"))
	e.GET("/admin/report").Expect().Status(http.StatusInternalServerError).JSON().Object().HasValue("error", "db_error")
}

func TestBuildReport(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	ts := func(age time.Duration) int64 { return now.Add(-age).Unix() }
	day := 24 * time.Hour
	activity := []acmedns.DomainActivity{
		{Subdomain: "never", LastUpdate: 0, HasTXT: false},
		{Subdomain: "fresh", LastUpdate: ts(1 * time.Hour), HasTXT: true},
		{Subdomain: "week", LastUpdate: ts(3 * day), HasTXT: true},
		{Subdomain: "month", LastUpdate: ts(20 * day), HasTXT: true},
		{Subdomain: "quarter", LastUpdate: ts(60 * day), HasTXT: true},
		{Subdomain: "stale", LastUpdate: ts(200 * day), HasTXT: true},
		{Subdomain: "stale-empty", LastUpdate: ts(400 * day), HasTXT: false},
	}

	counts, recent := BuildReport(activity, now, 3)
	expected := AdminReportCounts{
		Total:          7,
		WithTXT:        5,
		NeverUpdated:   1,
		UpdatedLast24h: 1,
		UpdatedLast7d:  2,
		UpdatedLast30d: 3,
		UpdatedLast90d: 4,
		Stale:          2,
	}
	if counts != expected {
		t.Errorf("Unexpected counts: got %+v, expected %+v", counts, expected)
	}
	if len(recent) != 3 {
		t.Fatalf("Expected 3 recent entries, got %d", len(recent))
	}
	for i, want := range []string{"fresh", "week", "month"} {
		if recent[i].Subdomain != want {
			t.Errorf("Recent entry %d: expected %s, got %s", i, want, recent[i].Subdomain)
		}
	}

	_, all := BuildReport(activity, now, -1)
	if len(all) != 6 {
		t.Errorf("Expected all 6 updated entries with negative limit, got %d", len(all))
	}
	counts, none := BuildReport(nil, now, 5)
	if counts.Total != 0 || len(none) != 0 {
		t.Errorf("Expected empty report for no activity, got %+v / %d", counts, len(none))
	}
}

func setupAdminWriteRouter() http.Handler {
	cfg := acmedns.DNSConfig{
		General:  acmedns.GeneralConfig{Domain: "auth.example.org"},
		Database: acmedns.DatabaseSettings{Engine: "sqlite3", Connection: ":memory:"},
		API:      acmedns.APIConfig{HeaderName: "X-Forwarded-For"},
		Admin:    acmedns.AdminConfig{Enabled: true, APIKey: testAdminKey},
	}
	a := &API{Config: &cfg, DB: testDB}
	router := httprouter.New()
	router.GET("/admin/domains/:subdomain", a.AdminAuth(a.AdminGetDomain))
	router.DELETE("/admin/domains/:subdomain", a.AdminAuth(a.AdminDeleteDomain))
	router.POST("/admin/domains/:subdomain/txt", a.AdminAuth(a.AdminSetTXT))
	return router
}

func TestAdminDeleteDomain(t *testing.T) {
	server := httptest.NewServer(setupAdminWriteRouter())
	defer server.Close()
	e := adminExpect(t, server)

	newUser, err := testDB.Register(acmedns.CIDRSlice{})
	if err != nil {
		t.Fatalf("Could not create new user, got error [%v]", err)
	}

	// Authentication is enforced on write endpoints as well
	getExpect(t, server).DELETE("/admin/domains/" + newUser.Subdomain).Expect().Status(http.StatusUnauthorized)
	if _, err := testDB.GetDomain(newUser.Subdomain); err != nil {
		t.Fatalf("Domain must still exist after unauthorized delete, got [%v]", err)
	}

	e.DELETE("/admin/domains/" + newUser.Subdomain).Expect().Status(http.StatusNoContent).NoContent()
	e.GET("/admin/domains/" + newUser.Subdomain).Expect().Status(http.StatusNotFound)
	e.DELETE("/admin/domains/"+newUser.Subdomain).Expect().
		Status(http.StatusNotFound).
		JSON().Object().HasValue("error", "not_found")
	e.DELETE("/admin/domains/not_valid.subdomain").Expect().
		Status(http.StatusBadRequest).
		JSON().Object().HasValue("error", "bad_subdomain")
}

func TestAdminSetTXT(t *testing.T) {
	server := httptest.NewServer(setupAdminWriteRouter())
	defer server.Close()
	e := adminExpect(t, server)

	newUser, err := testDB.Register(acmedns.CIDRSlice{})
	if err != nil {
		t.Fatalf("Could not create new user, got error [%v]", err)
	}
	txt1 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	txt2 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	txt3 := "ccccccccccccccccccccccccccccccccccccccccccc"
	path := "/admin/domains/" + newUser.Subdomain + "/txt"

	getExpect(t, server).POST(path).WithJSON(map[string]string{"txt": txt1}).Expect().Status(http.StatusUnauthorized)

	resp := e.POST(path).WithJSON(map[string]string{"txt": txt1}).Expect().
		Status(http.StatusOK).
		JSON().Object()
	resp.HasValue("subdomain", newUser.Subdomain)
	resp.HasValue("has_txt", true)
	resp.Value("txt_records").Array().Value(0).Object().HasValue("txt", txt1)

	// Second value fills the second slot, third value rolls over the oldest one
	e.POST(path).WithJSON(map[string]string{"txt": txt2}).Expect().Status(http.StatusOK)
	e.POST(path).WithJSON(map[string]string{"txt": txt3}).Expect().Status(http.StatusOK)
	served, err := testDB.GetTXTForDomain(newUser.Subdomain)
	if err != nil {
		t.Fatalf("GetTXTForDomain failed: [%v]", err)
	}
	if len(served) != 2 {
		t.Fatalf("Expected 2 TXT values, got %v", served)
	}
	for _, v := range served {
		if v != txt2 && v != txt3 {
			t.Errorf("Unexpected TXT value %q served, expected %q and %q", v, txt2, txt3)
		}
	}

	e.POST(path).WithJSON(map[string]string{"txt": "tooshort"}).Expect().
		Status(http.StatusBadRequest).
		JSON().Object().HasValue("error", "bad_txt")
	e.POST(path).WithBytes([]byte("{not json")).Expect().
		Status(http.StatusBadRequest).
		JSON().Object().HasValue("error", "malformed_json_payload")
	e.POST(path).WithJSON(map[string]int{"txt": 1234}).Expect().
		Status(http.StatusBadRequest).
		JSON().Object().HasValue("error", "malformed_json_payload")
	e.POST("/admin/domains/a097455b-52cc-4569-90c8-7a4b97c6eba8/txt").WithJSON(map[string]string{"txt": txt1}).Expect().
		Status(http.StatusNotFound).
		JSON().Object().HasValue("error", "not_found")
	e.POST("/admin/domains/not_valid.subdomain/txt").WithJSON(map[string]string{"txt": txt1}).Expect().
		Status(http.StatusBadRequest).
		JSON().Object().HasValue("error", "bad_subdomain")
}

func TestAdminWriteDBErrors(t *testing.T) {
	server := httptest.NewServer(setupAdminWriteRouter())
	defer server.Close()
	e := adminExpect(t, server)
	txt := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sub := "a097455b-52cc-4569-90c8-7a4b97c6eba8"
	domainRows := func() *sqlmock.Rows {
		return sqlmock.NewRows([]string{"Username", "Subdomain", "AllowFrom", "Value", "LastUpdate"}).
			AddRow("c36f50e8-4632-44f0-83fe-e070fef28a10", sub, "[]", "", 0)
	}

	oldDb := testDB.GetBackend()
	db, mock, _ := sqlmock.New()
	testDB.SetBackend(db)
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)
	defer testDB.SetBackend(oldDb)

	mock.ExpectBegin().WillReturnError(errors.New("error"))
	e.DELETE("/admin/domains/"+sub).Expect().Status(http.StatusInternalServerError).JSON().Object().HasValue("error", "db_error")

	mock.ExpectQuery("SELECT r.Username").WillReturnError(errors.New("error"))
	e.POST("/admin/domains/"+sub+"/txt").WithJSON(map[string]string{"txt": txt}).Expect().
		Status(http.StatusInternalServerError).JSON().Object().HasValue("error", "db_error")

	mock.ExpectQuery("SELECT r.Username").WillReturnRows(domainRows())
	mock.ExpectPrepare("UPDATE txt").WillReturnError(errors.New("error"))
	e.POST("/admin/domains/"+sub+"/txt").WithJSON(map[string]string{"txt": txt}).Expect().
		Status(http.StatusInternalServerError).JSON().Object().HasValue("error", "db_error")

	mock.ExpectQuery("SELECT r.Username").WillReturnRows(domainRows())
	mock.ExpectPrepare("UPDATE txt").ExpectExec().WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT r.Username").WillReturnError(errors.New("error"))
	e.POST("/admin/domains/"+sub+"/txt").WithJSON(map[string]string{"txt": txt}).Expect().
		Status(http.StatusInternalServerError).JSON().Object().HasValue("error", "db_error")
}
