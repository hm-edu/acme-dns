package main

import (
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/hm-edu/acme-dns/pkg/acmedns"
	"github.com/hm-edu/acme-dns/pkg/database"
	"github.com/hm-edu/acme-dns/pkg/nameserver"
	"github.com/stretchr/testify/assert"
)

func TestAcme(t *testing.T) {
	cfg := acmedns.DNSConfig{
		General: acmedns.GeneralConfig{
			Domain:  "auth.example.org",
			Listen:  "127.0.0.1:15353",
			Proto:   "udp",
			Nsname:  "ns1.auth.example.org",
			Nsadmin: "admin.example.org",
			Debug:   false,
		},
		Database: acmedns.DatabaseSettings{
			Engine:     "sqlite3",
			Connection: ":memory:",
		},
		API: acmedns.APIConfig{
			TLS: "letsencryptstaging",
		},
	}

	db := database.New()
	_ = db.Init("sqlite3", ":memory:")

	srv := nameserver.New(db, cfg.General.Listen, cfg.General.Proto, cfg.General.Domain)
	srv.ParseRecords(cfg)
	servers := []*nameserver.DNSServer{srv}
	magic := setupAcme(&cfg, servers)
	assert.Len(t, magic.Issuers, 1)

	if manager, ok := magic.Issuers[0].(*certmagic.ACMEIssuer); ok {
		assert.Equal(t, manager.CA, certmagic.LetsEncryptStagingCA)
	}
}
