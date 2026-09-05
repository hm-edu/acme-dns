package acmedns

import (
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestSetupLogging(t *testing.T) {
	for i, test := range []struct {
		format   string
		level    string
		expected string
	}{
		{"text", "warning", "warning"},
		{"json", "debug", "debug"},
		{"text", "info", "info"},
		{"json", "error", "error"},
		{"text", "something", "warning"},
	} {
		SetupLogging(test.format, test.level)
		if log.GetLevel().String() != test.expected {
			t.Errorf("Test %d: Expected loglevel %s but got %s", i, test.expected, log.GetLevel().String())
		}
	}
}

func TestReadConfig(t *testing.T) {
	for i, test := range []struct {
		inFile []byte
		output DNSConfig
	}{
		{
			[]byte("[general]\nlisten = \":53\"\ndebug = true\n[api]\napi_domain = \"something.strange\""),
			DNSConfig{
				General: GeneralConfig{
					Listen: ":53",
					Debug:  true,
				},
				API: APIConfig{
					Domain: "something.strange",
				},
			},
		},
		{
			[]byte("[\x00[[[[[[[[[de\nlisten =]"),
			DNSConfig{},
		},
	} {
		tmpfile, err := os.CreateTemp("", "acmedns")
		if err != nil {
			t.Error("Could not create temporary file")
		}
		defer func(name string) {
			_ = os.Remove(name)
		}(tmpfile.Name())

		if _, err := tmpfile.Write(test.inFile); err != nil {
			t.Error("Could not write to temporary file")
		}

		if err := tmpfile.Close(); err != nil {
			t.Error("Could not close temporary file")
		}
		ret, _ := ReadConfig(tmpfile.Name())
		if ret.General.Listen != test.output.General.Listen {
			t.Errorf("Test %d: Expected listen value %s, but got %s", i, test.output.General.Listen, ret.General.Listen)
		}
		if ret.API.Domain != test.output.API.Domain {
			t.Errorf("Test %d: Expected HTTP API domain %s, but got %s", i, test.output.API.Domain, ret.API.Domain)
		}
	}
}

func TestGetIPListFromHeader(t *testing.T) {
	for i, test := range []struct {
		input  string
		output []string
	}{
		{"1.1.1.1, 2.2.2.2", []string{"1.1.1.1", "2.2.2.2"}},
		{" 1.1.1.1 , 2.2.2.2", []string{"1.1.1.1", "2.2.2.2"}},
		{",1.1.1.1 ,2.2.2.2", []string{"1.1.1.1", "2.2.2.2"}},
	} {
		res := GetIPListFromHeader(test.input)
		if len(res) != len(test.output) {
			t.Errorf("Test %d: Expected [%d] items in return list, but got [%d]", i, len(test.output), len(res))
		} else {
			for j, vv := range test.output {
				if res[j] != vv {
					t.Errorf("Test %d: Expected return value [%v] but got [%v]", j, test.output, res)
				}
			}
		}
	}
}

func TestAdminConfigValidate(t *testing.T) {
	longKey := "0123456789abcdef0123456789abcdef"
	for i, test := range []struct {
		cfg     AdminConfig
		wantErr bool
	}{
		{AdminConfig{Enabled: false}, false},
		{AdminConfig{Enabled: false, APIKey: "short"}, false},
		{AdminConfig{Enabled: true}, true},
		{AdminConfig{Enabled: true, APIKey: "short"}, true},
		{AdminConfig{Enabled: true, APIKey: longKey}, false},
		{AdminConfig{Enabled: true, APIKey: longKey, AllowFrom: CIDRSlice{"127.0.0.1/32", "[::1]/128"}}, false},
		{AdminConfig{Enabled: true, APIKey: longKey, AllowFrom: CIDRSlice{"127.0.0.1"}}, true},
		{AdminConfig{Enabled: true, APIKey: longKey, AllowFrom: CIDRSlice{"invalid"}}, true},
	} {
		err := test.cfg.Validate()
		if (err != nil) != test.wantErr {
			t.Errorf("Test %d: expected error=%v, got [%v]", i, test.wantErr, err)
		}
	}
}

func TestPrepareConfigAdmin(t *testing.T) {
	base := DNSConfig{Database: DatabaseSettings{Engine: "sqlite3", Connection: ":memory:"}}

	if _, err := PrepareConfig(base); err != nil {
		t.Errorf("Expected no error for config without admin section, got [%v]", err)
	}

	bad := base
	bad.Admin = AdminConfig{Enabled: true, APIKey: "tooshort"}
	if _, err := PrepareConfig(bad); err == nil {
		t.Errorf("Expected error for enabled admin API with short key, got none")
	}

	good := base
	good.Admin = AdminConfig{Enabled: true, APIKey: "0123456789abcdef0123456789abcdef", AllowFrom: CIDRSlice{"10.0.0.0/8"}}
	if _, err := PrepareConfig(good); err != nil {
		t.Errorf("Expected no error for valid admin config, got [%v]", err)
	}
}

func TestCIDRSliceAllows(t *testing.T) {
	empty := CIDRSlice{}
	if !empty.Allows("1.2.3.4") || !empty.AllowsAny([]string{}) || !empty.AllowsAny([]string{"whatever"}) {
		t.Errorf("Empty allowlist must allow everything")
	}
	onlyInvalid := CIDRSlice{"invalid", "1.2.3.4"}
	if !onlyInvalid.Allows("9.9.9.9") {
		t.Errorf("Allowlist with only invalid entries must allow everything")
	}
	acl := CIDRSlice{"192.168.1.0/24", "[2001:db8::]/32", "invalid"}
	for i, test := range []struct {
		ips      []string
		expected bool
	}{
		{[]string{"192.168.1.1"}, true},
		{[]string{"192.168.2.1"}, false},
		{[]string{"2001:db8:1::1"}, true},
		{[]string{"2001:db9::1"}, false},
		{[]string{"10.0.0.1", "192.168.1.200"}, true},
		{[]string{"10.0.0.1", "10.0.0.2"}, false},
		{[]string{}, false},
		{[]string{""}, false},
		{[]string{"not an ip"}, false},
	} {
		if got := acl.AllowsAny(test.ips); got != test.expected {
			t.Errorf("Test %d: AllowsAny(%v) = %v, expected %v", i, test.ips, got, test.expected)
		}
	}
}
