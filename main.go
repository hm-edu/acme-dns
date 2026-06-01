//go:build !test
// +build !test

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	stdlog "log"
	"net/http"
	"os"
	"strings"
	"syscall"

	"github.com/caddyserver/certmagic"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/hm-edu/acme-dns/pkg/acmedns"
	httpapi "github.com/hm-edu/acme-dns/pkg/api"
	"github.com/hm-edu/acme-dns/pkg/database"
	"github.com/hm-edu/acme-dns/pkg/nameserver"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
)

func main() {
	syscall.Umask(0077)
	configPtr := flag.String("c", "/etc/acme-dns/config.cfg", "config file location")
	flag.Parse()

	var err error
	var cfg acmedns.DNSConfig
	if acmedns.FileIsAccessible(*configPtr) {
		log.WithFields(log.Fields{"file": *configPtr}).Info("Using config file")
		cfg, err = acmedns.ReadConfig(*configPtr)
	} else if acmedns.FileIsAccessible("./config.cfg") {
		log.WithFields(log.Fields{"file": "./config.cfg"}).Info("Using config file")
		cfg, err = acmedns.ReadConfig("./config.cfg")
	} else {
		log.Errorf("Configuration file not found.")
		os.Exit(1)
	}
	if err != nil {
		log.Errorf("Encountered an error while trying to read configuration file:  %s", err)
		os.Exit(1)
	}

	acmedns.SetupLogging(cfg.Logconfig.Format, cfg.Logconfig.Level)

	db := database.New()
	err = db.Init(cfg.Database.Engine, cfg.Database.Connection)
	if err != nil {
		log.Errorf("Could not open database [%v]", err)
		os.Exit(1)
	} else {
		log.Info("Connected to database")
	}
	defer db.Close()

	errChan := make(chan error, 1)

	dnsservers := make([]*nameserver.DNSServer, 0)
	if strings.HasPrefix(cfg.General.Proto, "both") {
		udpProto := "udp"
		tcpProto := "tcp"
		if strings.HasSuffix(cfg.General.Proto, "4") {
			udpProto += "4"
			tcpProto += "4"
		} else if strings.HasSuffix(cfg.General.Proto, "6") {
			udpProto += "6"
			tcpProto += "6"
		}
		dnsServerUDP := nameserver.New(db, cfg.General.Listen, udpProto, cfg.General.Domain)
		dnsservers = append(dnsservers, dnsServerUDP)
		dnsServerUDP.ParseRecords(cfg)
		dnsServerTCP := nameserver.New(db, cfg.General.Listen, tcpProto, cfg.General.Domain)
		dnsservers = append(dnsservers, dnsServerTCP)
		dnsServerTCP.Domains = dnsServerUDP.Domains
		dnsServerTCP.SOA = dnsServerUDP.SOA
		go dnsServerUDP.Start(errChan)
		go dnsServerTCP.Start(errChan)
	} else {
		dnsServer := nameserver.New(db, cfg.General.Listen, cfg.General.Proto, cfg.General.Domain)
		dnsservers = append(dnsservers, dnsServer)
		dnsServer.ParseRecords(cfg)
		go dnsServer.Start(errChan)
	}

	go startHTTPAPI(errChan, &cfg, db, dnsservers)

	for {
		err = <-errChan
		if err != nil {
			log.Fatal(err)
		}
	}
}

func startHTTPAPI(errChan chan error, cfg *acmedns.DNSConfig, db acmedns.Database, dnsservers []*nameserver.DNSServer) {
	logger := log.New()
	logwriter := logger.Writer()
	defer func(logwriter *io.PipeWriter) {
		_ = logwriter.Close()
	}(logwriter)
	stdlog.SetOutput(logwriter)
	legolog.Logger = logger

	router := httprouter.New()
	c := cors.New(cors.Options{
		AllowedOrigins:     cfg.API.CorsOrigins,
		AllowedMethods:     []string{"GET", "POST"},
		OptionsPassthrough: false,
		Debug:              cfg.General.Debug,
	})
	if cfg.General.Debug {
		c.Log = stdlog.New(logwriter, "", 0)
	}

	a := &httpapi.API{Config: cfg, DB: db}

	if !cfg.API.DisableRegistration {
		router.POST("/register", a.RegisterPost)
	}
	router.POST("/update", a.Auth(a.UpdatePost))
	router.GET("/health", httpapi.HealthCheck)

	host := cfg.API.IP + ":" + cfg.API.Port

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	var err error
	switch cfg.API.TLS {
	case "letsencryptstaging", "letsencrypt":
		magic := setupAcme(cfg, dnsservers)
		err = magic.ManageSync(context.Background(), []string{cfg.General.Domain})
		if err != nil {
			errChan <- err
			return
		}
		tlsCfg.GetCertificate = magic.GetCertificate
		srv := &http.Server{
			Addr:      host,
			Handler:   c.Handler(router),
			TLSConfig: tlsCfg,
			ErrorLog:  stdlog.New(logwriter, "", 0),
		}
		log.WithFields(log.Fields{"host": host, "domain": cfg.General.Domain}).Info("Listening HTTPS")
		err = srv.ListenAndServeTLS("", "")
	case "cert":
		srv := &http.Server{
			Addr:      host,
			Handler:   c.Handler(router),
			TLSConfig: tlsCfg,
			ErrorLog:  stdlog.New(logwriter, "", 0),
		}
		log.WithFields(log.Fields{"host": host}).Info("Listening HTTPS")
		err = srv.ListenAndServeTLS(cfg.API.TLSCertFullchain, cfg.API.TLSCertPrivkey)
	default:
		log.WithFields(log.Fields{"host": host}).Info("Listening HTTP")
		err = http.ListenAndServe(host, c.Handler(router))
	}
	if err != nil {
		errChan <- err
	}
}

func setupAcme(cfg *acmedns.DNSConfig, dnsservers []*nameserver.DNSServer) *certmagic.Config {
	ca := certmagic.LetsEncryptStagingCA
	if cfg.API.TLS == "letsencrypt" {
		ca = certmagic.LetsEncryptProductionCA
	}

	provider := nameserver.NewChallengeProvider(dnsservers)

	storage := certmagic.FileStorage{Path: cfg.API.ACMECacheDir}

	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
	})
	magic = certmagic.New(cache, certmagic.Config{
		DefaultServerName: cfg.General.Domain,
		Storage:           &storage,
	})
	acme := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
		CA:     ca,
		Email:  cfg.API.NotificationEmail,
		Agreed: true,
		DNS01Solver: &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{
			DNSProvider: &provider,
			Resolvers:   cfg.General.Resolvers,
		}},
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
	})

	magic.Issuers = []certmagic.Issuer{acme}
	return magic
}
