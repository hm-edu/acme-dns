package acmedns

import (
	"errors"
	"os"

	"github.com/BurntSushi/toml"
	log "github.com/sirupsen/logrus"
)

// DNSConfig holds the config structure
type DNSConfig struct {
	General   GeneralConfig
	Database  DatabaseSettings
	API       APIConfig
	Logconfig LogConfig
}

// GeneralConfig is the config file general section
type GeneralConfig struct {
	Listen        string
	Proto         string `toml:"protocol"`
	Domain        string
	Nsname        string
	Nsadmin       string
	Debug         bool
	StaticRecords []string `toml:"records"`
	Resolvers     []string `toml:"resolvers"`
}

// DatabaseSettings holds database connection settings
type DatabaseSettings struct {
	Engine     string
	Connection string
}

// APIConfig holds API config
type APIConfig struct {
	Domain              string `toml:"api_domain"`
	IP                  string
	DisableRegistration bool     `toml:"disable_registration"`
	AutocertPort        string   `toml:"autocert_port"`
	Port                string   `toml:"port"`
	TLS                 string
	TLSCertPrivkey      string   `toml:"tls_cert_privkey"`
	TLSCertFullchain    string   `toml:"tls_cert_fullchain"`
	ACMECacheDir        string   `toml:"acme_cache_dir"`
	NotificationEmail   string   `toml:"notification_email"`
	CorsOrigins         []string
	UseHeader           bool   `toml:"use_header"`
	HeaderName          string `toml:"header_name"`
}

// LogConfig holds logging config
type LogConfig struct {
	Level   string `toml:"loglevel"`
	Logtype string `toml:"logtype"`
	File    string `toml:"logfile"`
	Format  string `toml:"logformat"`
}

// FileIsAccessible checks whether a file is accessible
func FileIsAccessible(fname string) bool {
	_, err := os.Stat(fname)
	if err != nil {
		return false
	}
	f, err := os.Open(fname)
	if err != nil {
		return false
	}
	err = f.Close()
	return err == nil
}

// ReadConfig reads and parses the configuration file
func ReadConfig(fname string) (DNSConfig, error) {
	var conf DNSConfig
	_, err := toml.DecodeFile(fname, &conf)
	if err != nil {
		return conf, err
	}
	return PrepareConfig(conf)
}

// PrepareConfig checks that mandatory values exist, and sets defaults
func PrepareConfig(conf DNSConfig) (DNSConfig, error) {
	if conf.Database.Engine == "" {
		return conf, errors.New("missing database configuration option \"engine\"")
	}
	if conf.Database.Connection == "" {
		return conf, errors.New("missing database configuration option \"connection\"")
	}

	if conf.API.ACMECacheDir == "" {
		conf.API.ACMECacheDir = "api-certs"
	}

	return conf, nil
}

// SetupLogging configures the logrus logger
func SetupLogging(format string, level string) {
	if format == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	}
	switch level {
	default:
		log.SetLevel(log.WarnLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	}
}
