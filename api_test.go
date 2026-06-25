package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gavv/httpexpect"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/cors"
)

// noAuth function to write ACMETxt model to context while not preforming any validation
func noAuth(update httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		postData := ACMETxt{}
		uname := r.Header.Get("X-Api-User")
		passwd := r.Header.Get("X-Api-Key")

		dec := json.NewDecoder(r.Body)
		_ = dec.Decode(&postData)
		// Set user info to the decoded ACMETxt object
		postData.Username, _ = uuid.Parse(uname)
		postData.Password = passwd
		// Set the ACMETxt struct to context to pull in from update function
		ctx := r.Context()
		ctx = context.WithValue(ctx, ACMETxtKey, postData)
		r = r.WithContext(ctx)
		update(w, r, p)
	}
}

func getExpect(t *testing.T, server *httptest.Server) *httpexpect.Expect {
	return httpexpect.WithConfig(httpexpect.Config{
		BaseURL:  server.URL,
		Reporter: httpexpect.NewAssertReporter(t),
		Printers: []httpexpect.Printer{
			httpexpect.NewCurlPrinter(t),
			httpexpect.NewDebugPrinter(t, true),
		},
	})
}

func setupRouter(debug bool, noauth bool) http.Handler {
	api := httprouter.New()
	var dbcfg = dbsettings{
		Engine:     "sqlite3",
		Connection: ":memory:"}
	var httpapicfg = httpapi{
		Domain:      "",
		Port:        "8080",
		TLS:         "none",
		CorsOrigins: []string{"*"},
		UseHeader:   true,
		HeaderName:  "X-Forwarded-For",
	}
	var dnscfg = DNSConfig{
		API:      httpapicfg,
		Database: dbcfg,
	}
	Config = dnscfg
	c := cors.New(cors.Options{
		AllowedOrigins:     Config.API.CorsOrigins,
		AllowedMethods:     []string{"GET", "POST"},
		OptionsPassthrough: false,
		Debug:              Config.General.Debug,
	})
	api.POST("/register", webRegisterPost)
	api.GET("/health", healthCheck)
	if noauth {
		api.POST("/update", noAuth(webUpdatePost))
	} else {
		api.POST("/update", Auth(webUpdatePost))
	}
	return c.Handler(api)
}

func TestApiRegister(t *testing.T) {
	router := setupRouter(false, false)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	e.POST("/register").Expect().
		Status(http.StatusCreated).
		JSON().Object().
		ContainsKey("fulldomain").
		ContainsKey("subdomain").
		ContainsKey("username").
		ContainsKey("password").
		NotContainsKey("error")

	allowfrom := map[string][]interface{}{
		"allowfrom": []interface{}{"123.123.123.123/32",
			"2001:db8:a0b:12f0::1/32",
			"[::1]/64",
		},
	}

	response := e.POST("/register").
		WithJSON(allowfrom).
		Expect().
		Status(http.StatusCreated).
		JSON().Object().
		ContainsKey("fulldomain").
		ContainsKey("subdomain").
		ContainsKey("username").
		ContainsKey("password").
		ContainsKey("allowfrom").
		NotContainsKey("error")

	response.Value("allowfrom").Array().Elements("123.123.123.123/32", "2001:db8:a0b:12f0::1/32", "::1/64")
}

func TestApiRegisterBadAllowFrom(t *testing.T) {
	router := setupRouter(false, false)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	invalidVals := []string{
		"invalid",
		"1.2.3.4/33",
		"1.2/24",
		"1.2.3.4",
		"12345:db8:a0b:12f0::1/32",
		"1234::123::123::1/32",
	}

	for _, v := range invalidVals {

		allowfrom := map[string][]interface{}{
			"allowfrom": []interface{}{v}}

		response := e.POST("/register").
			WithJSON(allowfrom).
			Expect().
			Status(http.StatusBadRequest).
			JSON().Object().
			ContainsKey("error")

		response.Value("error").Equal("invalid_allowfrom_cidr")
	}
}

func TestApiRegisterMalformedJSON(t *testing.T) {
	router := setupRouter(false, false)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)

	malPayloads := []string{
		"{\"allowfrom': '1.1.1.1/32'}",
		"\"allowfrom\": \"1.1.1.1/32\"",
		"{\"allowfrom\": \"[1.1.1.1/32]\"",
		"\"allowfrom\": \"1.1.1.1/32\"}",
		"{allowfrom: \"1.2.3.4\"}",
		"{allowfrom: [1.2.3.4]}",
		"whatever that's not a json payload",
	}
	for _, test := range malPayloads {
		e.POST("/register").
			WithBytes([]byte(test)).
			Expect().
			Status(http.StatusBadRequest).
			JSON().Object().
			ContainsKey("error").
			NotContainsKey("subdomain").
			NotContainsKey("username")
	}
}

func TestApiRegisterWithMockDB(t *testing.T) {
	router := setupRouter(false, false)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	oldDb := DB.GetBackend()
	db, mock, _ := sqlmock.New()
	DB.SetBackend(db)
	defer func() {
		_ = db.Close()
	}()
	mock.ExpectBegin()
	mock.ExpectPrepare("INSERT INTO records").WillReturnError(errors.New("error"))
	e.POST("/register").Expect().
		Status(http.StatusInternalServerError).
		JSON().Object().
		ContainsKey("error")
	DB.SetBackend(oldDb)
}

func TestApiUpdateWithInvalidSubdomain(t *testing.T) {
	validTxtData := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	updateJSON := map[string]interface{}{
		"subdomain": "",
		"txt":       ""}

	router := setupRouter(false, false)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	newUser, err := DB.Register(cidrslice{})
	if err != nil {
		t.Errorf("Could not create new user, got error [%v]", err)
	}
	// Invalid subdomain data
	updateJSON["subdomain"] = "example.com"
	updateJSON["txt"] = validTxtData
	e.POST("/update").
		WithJSON(updateJSON).
		WithHeader("X-Api-User", newUser.Username.String()).
		WithHeader("X-Api-Key", newUser.Password).
		Expect().
		Status(http.StatusUnauthorized).
		JSON().Object().
		ContainsKey("error").
		NotContainsKey("txt").
		ValueEqual("error", "forbidden")
}

func TestApiUpdateWithInvalidTxt(t *testing.T) {
	invalidTXTData := "idk m8 bbl lmao"

	updateJSON := map[string]interface{}{
		"subdomain": "",
		"txt":       ""}

	router := setupRouter(false, false)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	newUser, err := DB.Register(cidrslice{})
	if err != nil {
		t.Errorf("Could not create new user, got error [%v]", err)
	}
	updateJSON["subdomain"] = newUser.Subdomain
	// Invalid txt data
	updateJSON["txt"] = invalidTXTData
	e.POST("/update").
		WithJSON(updateJSON).
		WithHeader("X-Api-User", newUser.Username.String()).
		WithHeader("X-Api-Key", newUser.Password).
		Expect().
		Status(http.StatusBadRequest).
		JSON().Object().
		ContainsKey("error").
		NotContainsKey("txt").
		ValueEqual("error", "bad_txt")
}

func TestApiUpdateWithoutCredentials(t *testing.T) {
	router := setupRouter(false, false)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	e.POST("/update").Expect().
		Status(http.StatusUnauthorized).
		JSON().Object().
		ContainsKey("error").
		NotContainsKey("txt")
}

func TestApiUpdateWithCredentials(t *testing.T) {
	validTxtData := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	updateJSON := map[string]interface{}{
		"subdomain": "",
		"txt":       ""}

	router := setupRouter(false, false)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	newUser, err := DB.Register(cidrslice{})
	if err != nil {
		t.Errorf("Could not create new user, got error [%v]", err)
	}
	// Valid data
	updateJSON["subdomain"] = newUser.Subdomain
	updateJSON["txt"] = validTxtData
	e.POST("/update").
		WithJSON(updateJSON).
		WithHeader("X-Api-User", newUser.Username.String()).
		WithHeader("X-Api-Key", newUser.Password).
		Expect().
		Status(http.StatusOK).
		JSON().Object().
		ContainsKey("txt").
		NotContainsKey("error").
		ValueEqual("txt", validTxtData)
}

func TestApiUpdateWithCredentialsMockDB(t *testing.T) {
	validTxtData := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	updateJSON := map[string]interface{}{
		"subdomain": "",
		"txt":       ""}

	// Valid data
	updateJSON["subdomain"] = "a097455b-52cc-4569-90c8-7a4b97c6eba8"
	updateJSON["txt"] = validTxtData

	router := setupRouter(false, true)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	oldDb := DB.GetBackend()
	db, mock, _ := sqlmock.New()
	DB.SetBackend(db)
	defer func() {
		_ = db.Close()
	}()
	mock.ExpectBegin()
	mock.ExpectPrepare("UPDATE records").WillReturnError(errors.New("error"))
	e.POST("/update").
		WithJSON(updateJSON).
		Expect().
		Status(http.StatusInternalServerError).
		JSON().Object().
		ContainsKey("error")
	DB.SetBackend(oldDb)
}

func TestApiManyUpdateWithCredentials(t *testing.T) {
	validTxtData := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	router := setupRouter(true, false)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	// User without defined CIDR masks
	newUser, err := DB.Register(cidrslice{})
	if err != nil {
		t.Errorf("Could not create new user, got error [%v]", err)
	}

	// User with defined allow from - CIDR masks, all invalid
	// (httpexpect doesn't provide a way to mock remote ip)
	newUserWithCIDR, err := DB.Register(cidrslice{"192.168.1.1/32", "invalid"})
	if err != nil {
		t.Errorf("Could not create new user with CIDR, got error [%v]", err)
	}

	// Another user with valid CIDR mask to match the httpexpect default
	newUserWithValidCIDR, err := DB.Register(cidrslice{"10.1.2.3/32", "invalid"})
	if err != nil {
		t.Errorf("Could not create new user with a valid CIDR, got error [%v]", err)
	}

	for _, test := range []struct {
		user      string
		pass      string
		subdomain string
		txt       interface{}
		status    int
	}{
		{"non-uuid-user", "tooshortpass", "non-uuid-subdomain", validTxtData, 401},
		{"a097455b-52cc-4569-90c8-7a4b97c6eba8", "tooshortpass", "bb97455b-52cc-4569-90c8-7a4b97c6eba8", validTxtData, 401},
		{"a097455b-52cc-4569-90c8-7a4b97c6eba8", "LongEnoughPassButNoUserExists___________", "bb97455b-52cc-4569-90c8-7a4b97c6eba8", validTxtData, 401},
		{newUser.Username.String(), newUser.Password, "a097455b-52cc-4569-90c8-7a4b97c6eba8", validTxtData, 401},
		{newUser.Username.String(), newUser.Password, newUser.Subdomain, "tooshortfortxt", 400},
		{newUser.Username.String(), newUser.Password, newUser.Subdomain, 1234567890, 400},
		{newUser.Username.String(), newUser.Password, newUser.Subdomain, validTxtData, 200},
		{newUserWithCIDR.Username.String(), newUserWithCIDR.Password, newUserWithCIDR.Subdomain, validTxtData, 401},
		{newUserWithValidCIDR.Username.String(), newUserWithValidCIDR.Password, newUserWithValidCIDR.Subdomain, validTxtData, 200},
		{newUser.Username.String(), "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", newUser.Subdomain, validTxtData, 401},
	} {
		updateJSON := map[string]interface{}{
			"subdomain": test.subdomain,
			"txt":       test.txt}
		e.POST("/update").
			WithJSON(updateJSON).
			WithHeader("X-Api-User", test.user).
			WithHeader("X-Api-Key", test.pass).
			WithHeader("X-Forwarded-For", "10.1.2.3").
			Expect().
			Status(test.status)
	}
}

func TestApiManyUpdateWithIpCheckHeaders(t *testing.T) {

	router := setupRouter(false, false)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	// Use header checks from default header (X-Forwarded-For)
	Config.API.UseHeader = true
	// User without defined CIDR masks
	newUser, err := DB.Register(cidrslice{})
	if err != nil {
		t.Errorf("Could not create new user, got error [%v]", err)
	}

	newUserWithCIDR, err := DB.Register(cidrslice{"192.168.1.2/32", "invalid"})
	if err != nil {
		t.Errorf("Could not create new user with CIDR, got error [%v]", err)
	}

	newUserWithIP6CIDR, err := DB.Register(cidrslice{"2002:c0a8::0/32"})
	if err != nil {
		t.Errorf("Could not create a new user with IP6 CIDR, got error [%v]", err)
	}

	for _, test := range []struct {
		user        ACMETxt
		headerValue string
		status      int
	}{
		{newUser, "whatever goes", 200},
		{newUser, "10.0.0.1, 1.2.3.4 ,3.4.5.6", 200},
		{newUserWithCIDR, "127.0.0.1", 401},
		{newUserWithCIDR, "10.0.0.1, 10.0.0.2, 192.168.1.3", 401},
		{newUserWithCIDR, "10.1.1.1 ,192.168.1.2, 8.8.8.8", 200},
		{newUserWithIP6CIDR, "2002:c0a8:b4dc:0d3::0", 200},
		{newUserWithIP6CIDR, "2002:c0a7:0ff::0", 401},
		{newUserWithIP6CIDR, "2002:c0a8:d3ad:b33f:c0ff:33b4:dc0d:3b4d", 200},
	} {
		updateJSON := map[string]interface{}{
			"subdomain": test.user.Subdomain,
			"txt":       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
		e.POST("/update").
			WithJSON(updateJSON).
			WithHeader("X-Api-User", test.user.Username.String()).
			WithHeader("X-Api-Key", test.user.Password).
			WithHeader("X-Forwarded-For", test.headerValue).
			Expect().
			Status(test.status)
	}
	Config.API.UseHeader = false
}

func TestApiHealthCheck(t *testing.T) {
	router := setupRouter(false, false)
	server := httptest.NewServer(router)
	defer server.Close()
	e := getExpect(t, server)
	e.GET("/health").Expect().Status(http.StatusOK)
}

func setupAdminRouter(t *testing.T, token string) (*httptest.Server, *httpexpect.Expect) {
	t.Helper()
	api := httprouter.New()
	var dbcfg = dbsettings{Engine: "sqlite3", Connection: ":memory:"}
	var httpapicfg = httpapi{
		Port:        "8080",
		TLS:         "none",
		CorsOrigins: []string{"*"},
		UseHeader:   false,
		HeaderName:  "X-Forwarded-For",
		Admin:       adminconfig{Token: token},
	}
	Config = DNSConfig{API: httpapicfg, Database: dbcfg}
	newDB := new(acmedb)
	_ = newDB.Init(Config.Database.Engine, Config.Database.Connection)
	oldDB := DB
	DB = newDB
	t.Cleanup(func() { DB = oldDB })

	api.POST("/register", webRegisterPost)
	api.GET("/health", healthCheck)
	api.POST("/update", Auth(webUpdatePost))
	api.GET("/admin/records", adminBearerMiddleware(adminListRecords))
	api.POST("/admin/records", adminBearerMiddleware(adminCreateRecord))
	api.PUT("/admin/records/:id", adminBearerMiddleware(adminUpdateRecord))
	api.DELETE("/admin/records/:id", adminBearerMiddleware(adminDeleteRecord))
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
	})
	server := httptest.NewServer(c.Handler(api))
	t.Cleanup(func() { server.Close() })
	e := getExpect(t, server)
	return server, e
}

func TestAdminListRecordsUnauthorized(t *testing.T) {
	_, e := setupAdminRouter(t, "test-token")
	e.GET("/admin/records").Expect().Status(http.StatusUnauthorized)
}

func TestAdminCreateRecord(t *testing.T) {
	_, e := setupAdminRouter(t, "test-token")

	body := map[string]interface{}{"name": "test.example.com", "type": "A", "value": "1.2.3.4", "ttl": 300}
	e.POST("/admin/records").
		WithHeader("Authorization", "Bearer test-token").
		WithJSON(body).
		Expect().
		Status(http.StatusCreated).
		JSON().Object().ContainsKey("id")
}

func TestAdminCreateRecordInvalidType(t *testing.T) {
	_, e := setupAdminRouter(t, "test-token")

	body := map[string]interface{}{"name": "test.example.com", "type": "INVALID", "value": "1.2.3.4", "ttl": 300}
	e.POST("/admin/records").
		WithHeader("Authorization", "Bearer test-token").
		WithJSON(body).
		Expect().
		Status(http.StatusBadRequest)
}

func TestAdminListRecords(t *testing.T) {
	_, e := setupAdminRouter(t, "test-token")

	body := map[string]interface{}{"name": "test.example.com", "type": "A", "value": "1.2.3.4", "ttl": 60}
	created := e.POST("/admin/records").
		WithHeader("Authorization", "Bearer test-token").
		WithJSON(body).
		Expect().
		Status(http.StatusCreated).
		JSON().Object()
	createdID := created.Value("id").String().Raw()

	arr := e.GET("/admin/records").
		WithHeader("Authorization", "Bearer test-token").
		Expect().
		Status(http.StatusOK).
		JSON().Array()

	arr.Length().Equal(1)

	// Verify the created record appears in the list
	found := false
	for _, item := range arr.Iter() {
		if item.Object().Value("id").String().Raw() == createdID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("created record id %s not found in list", createdID)
	}
}

func TestAdminDeleteRecord(t *testing.T) {
	_, e := setupAdminRouter(t, "test-token")

	body := map[string]interface{}{"name": "del.example.com", "type": "A", "value": "1.2.3.4", "ttl": 60}
	id := e.POST("/admin/records").
		WithHeader("Authorization", "Bearer test-token").
		WithJSON(body).
		Expect().Status(http.StatusCreated).
		JSON().Object().Value("id").String().Raw()

	e.DELETE("/admin/records/"+id).
		WithHeader("Authorization", "Bearer test-token").
		Expect().Status(http.StatusNoContent)

	e.GET("/admin/records").
		WithHeader("Authorization", "Bearer test-token").
		Expect().
		Status(http.StatusOK).
		JSON().Array().Length().Equal(0)
}

func TestAdminUpdateRecord(t *testing.T) {
	_, e := setupAdminRouter(t, "test-token")

	// Create a record
	body := map[string]interface{}{"name": "upd.example.com", "type": "A", "value": "1.2.3.4", "ttl": 60}
	id := e.POST("/admin/records").
		WithHeader("Authorization", "Bearer test-token").
		WithJSON(body).
		Expect().Status(http.StatusCreated).
		JSON().Object().Value("id").String().Raw()

	// Update it with a new value and TTL
	updBody := map[string]interface{}{"name": "upd.example.com", "type": "A", "value": "5.6.7.8", "ttl": 120}
	obj := e.PUT("/admin/records/"+id).
		WithHeader("Authorization", "Bearer test-token").
		WithJSON(updBody).
		Expect().Status(http.StatusOK).
		JSON().Object()
	obj.Value("value").String().Equal("5.6.7.8")
	obj.Value("ttl").Number().Equal(120)

	// Not-found case: PUT to a non-existent UUID
	nonExistent := "00000000-0000-0000-0000-000000000000"
	e.PUT("/admin/records/"+nonExistent).
		WithHeader("Authorization", "Bearer test-token").
		WithJSON(updBody).
		Expect().Status(http.StatusNotFound)

	// Invalid-type case: should return 400
	invalidTypeBody := map[string]interface{}{"name": "upd.example.com", "type": "INVALID", "value": "5.6.7.8", "ttl": 60}
	e.PUT("/admin/records/"+id).
		WithHeader("Authorization", "Bearer test-token").
		WithJSON(invalidTypeBody).
		Expect().Status(http.StatusBadRequest)
}

func TestAdminWrongToken(t *testing.T) {
	_, e := setupAdminRouter(t, "correct-token")
	e.GET("/admin/records").WithHeader("Authorization", "Bearer wrong-token").Expect().Status(http.StatusUnauthorized)
}

func TestAdminCreateRecordInvalidValue(t *testing.T) {
	_, e := setupAdminRouter(t, "test-token")
	payload := map[string]interface{}{
		"name":  "test.example.com",
		"type":  "A",
		"value": "not-an-ip",
		"ttl":   60,
	}
	e.POST("/admin/records").
		WithHeader("Authorization", "Bearer test-token").
		WithJSON(payload).
		Expect().Status(http.StatusBadRequest)
}

func TestAdminCreateRecordInvalidMXValue(t *testing.T) {
	_, e := setupAdminRouter(t, "test-token")
	payload := map[string]interface{}{
		"name":  "test.example.com",
		"type":  "MX",
		"value": "not-a-valid-mx",
		"ttl":   60,
	}
	e.POST("/admin/records").
		WithHeader("Authorization", "Bearer test-token").
		WithJSON(payload).
		Expect().Status(http.StatusBadRequest)
}

func TestAdminCreateCAARecord(t *testing.T) {
	_, e := setupAdminRouter(t, "test-token")
	payload := map[string]interface{}{
		"name":  "caa.example.com",
		"type":  "CAA",
		"value": `0 issue "letsencrypt.org"`,
		"ttl":   300,
	}
	e.POST("/admin/records").
		WithHeader("Authorization", "Bearer test-token").
		WithJSON(payload).
		Expect().Status(http.StatusCreated).JSON().Object().ContainsKey("id")
}

func TestAdminTXTValueQuoteStripping(t *testing.T) {
	_, e := setupAdminRouter(t, "test-token")
	// Value submitted with surrounding quotes should be stored and returned without them.
	payload := map[string]interface{}{
		"name":  "txt.example.com",
		"type":  "TXT",
		"value": `"some token"`,
		"ttl":   60,
	}
	obj := e.POST("/admin/records").
		WithHeader("Authorization", "Bearer test-token").
		WithJSON(payload).
		Expect().Status(http.StatusCreated).JSON().Object()
	obj.Value("value").String().Equal("some token")
}

func TestAdminListRecordsFilter(t *testing.T) {
	_, e := setupAdminRouter(t, "test-token")
	// Create an A record and a CNAME record
	e.POST("/admin/records").
		WithHeader("Authorization", "Bearer test-token").
		WithJSON(map[string]interface{}{"name": "a.example.com", "type": "A", "value": "1.2.3.4", "ttl": 60}).
		Expect().Status(http.StatusCreated)
	e.POST("/admin/records").
		WithHeader("Authorization", "Bearer test-token").
		WithJSON(map[string]interface{}{"name": "b.example.com", "type": "CNAME", "value": "a.example.com", "ttl": 60}).
		Expect().Status(http.StatusCreated)
	// Filter by type=A — should only return 1 record
	e.GET("/admin/records").
		WithHeader("Authorization", "Bearer test-token").
		WithQuery("type", "A").
		Expect().Status(http.StatusOK).JSON().Array().Length().Equal(1)
	// Filter by name=b.example.com — should only return 1 record
	e.GET("/admin/records").
		WithHeader("Authorization", "Bearer test-token").
		WithQuery("name", "b.example.com").
		Expect().Status(http.StatusOK).JSON().Array().Length().Equal(1)
}

func setupRouterWithToken(t *testing.T, token string) (*httptest.Server, *httpexpect.Expect) {
	t.Helper()
	api := httprouter.New()
	var dbcfg = dbsettings{Engine: "sqlite3", Connection: ":memory:"}
	var httpapicfg = httpapi{
		Port:        "8080",
		TLS:         "none",
		CorsOrigins: []string{"*"},
		UseHeader:   false,
		HeaderName:  "X-Forwarded-For",
		Admin:       adminconfig{Token: token},
	}
	Config = DNSConfig{API: httpapicfg, Database: dbcfg}
	newDB := new(acmedb)
	_ = newDB.Init(Config.Database.Engine, Config.Database.Connection)
	oldDB := DB
	DB = newDB
	t.Cleanup(func() { DB = oldDB })

	api.GET("/health", healthCheck)
	if token != "" {
		api.GET("/admin/records", adminBearerMiddleware(adminListRecords))
		api.POST("/admin/records", adminBearerMiddleware(adminCreateRecord))
		api.PUT("/admin/records/:id", adminBearerMiddleware(adminUpdateRecord))
		api.DELETE("/admin/records/:id", adminBearerMiddleware(adminDeleteRecord))
	}
	server := httptest.NewServer(api)
	t.Cleanup(func() { server.Close() })
	return server, getExpect(t, server)
}

func TestAdminRoutesAbsentWithNoToken(t *testing.T) {
	_, e := setupRouterWithToken(t, "")
	e.GET("/admin/records").Expect().Status(http.StatusNotFound)
	e.POST("/admin/records").Expect().Status(http.StatusNotFound)
}

func TestAdminUpdatePreservesCreated(t *testing.T) {
	_, e := setupAdminRouter(t, "test-token")

	body := map[string]interface{}{"name": "ts.example.com", "type": "A", "value": "1.1.1.1", "ttl": 60}
	created := e.POST("/admin/records").
		WithHeader("Authorization", "Bearer test-token").
		WithJSON(body).
		Expect().Status(http.StatusCreated).
		JSON().Object()
	id := created.Value("id").String().Raw()
	originalCreated := created.Value("created").Number().Raw()

	updBody := map[string]interface{}{"name": "ts.example.com", "type": "A", "value": "2.2.2.2", "ttl": 120}
	updated := e.PUT("/admin/records/"+id).
		WithHeader("Authorization", "Bearer test-token").
		WithJSON(updBody).
		Expect().Status(http.StatusOK).
		JSON().Object()
	updated.Value("created").Number().Equal(originalCreated)
	updated.Value("value").String().Equal("2.2.2.2")
}
