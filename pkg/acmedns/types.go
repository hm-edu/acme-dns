package acmedns

import (
	"encoding/json"
	"net"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// ACMETxt is the default structure for the user controlled record
type ACMETxt struct {
	Username uuid.UUID
	Password string
	ACMETxtPost
	AllowFrom CIDRSlice
}

// ACMETxtPost holds the DNS part of the ACMETxt struct
type ACMETxtPost struct {
	Subdomain string `json:"subdomain"`
	Value     string `json:"txt"`
}

// CIDRSlice is a list of allowed CIDR ranges
type CIDRSlice []string

// JSON marshals CIDRSlice to a JSON string
func (c *CIDRSlice) JSON() string {
	ret, _ := json.Marshal(c.ValidEntries())
	return string(ret)
}

// IsValid checks that all entries in the slice are valid CIDR ranges
func (c *CIDRSlice) IsValid() error {
	for _, v := range *c {
		_, _, err := net.ParseCIDR(SanitizeIPv6addr(v))
		if err != nil {
			return err
		}
	}
	return nil
}

// ValidEntries returns only valid CIDR entries from the slice
func (c *CIDRSlice) ValidEntries() []string {
	valid := []string{}
	for _, v := range *c {
		_, _, err := net.ParseCIDR(SanitizeIPv6addr(v))
		if err == nil {
			valid = append(valid, SanitizeIPv6addr(v))
		}
	}
	return valid
}

// Allows checks if an IP address is within the allowed ranges. An empty (or
// completely invalid) slice allows every address.
func (c *CIDRSlice) Allows(ip string) bool {
	valid := c.ValidEntries()
	if len(valid) == 0 {
		return true
	}
	remoteIP := net.ParseIP(ip)
	log.WithFields(log.Fields{"ip": remoteIP}).Debug("Checking if access is permitted from IP")
	for _, v := range valid {
		_, vnet, _ := net.ParseCIDR(v)
		if vnet.Contains(remoteIP) {
			return true
		}
	}
	return false
}

// AllowsAny checks if any IP in the list is within the allowed ranges
func (c *CIDRSlice) AllowsAny(ips []string) bool {
	if len(ips) == 0 {
		return c.Allows("")
	}
	for _, v := range ips {
		if c.Allows(v) {
			return true
		}
	}
	return false
}

// AllowedFrom checks if an IP address is within the allowed ranges
func (a ACMETxt) AllowedFrom(ip string) bool {
	return a.AllowFrom.Allows(ip)
}

// AllowedFromList checks if any IP in the list is within the allowed ranges
func (a ACMETxt) AllowedFromList(ips []string) bool {
	return a.AllowFrom.AllowsAny(ips)
}

// NewACMETxt creates a new ACMETxt with a random password and UUID
func NewACMETxt() ACMETxt {
	var a = ACMETxt{}
	password := GeneratePassword(40)
	a.Username = uuid.New()
	a.Password = password
	a.Subdomain = uuid.New().String()
	return a
}

// TXTRecord is one of the rolling TXT values stored for a subdomain
type TXTRecord struct {
	Value string
	// LastUpdate is the unix timestamp of the last update, 0 if the value was never set
	LastUpdate int64
}

// DomainInfo is the administrative view of a registered subdomain
type DomainInfo struct {
	Username  uuid.UUID
	Subdomain string
	AllowFrom CIDRSlice
	TXT       []TXTRecord
}

// LastUpdate returns the unix timestamp of the most recent TXT update, 0 if the domain was never updated
func (d DomainInfo) LastUpdate() int64 {
	var last int64
	for _, t := range d.TXT {
		if t.LastUpdate > last {
			last = t.LastUpdate
		}
	}
	return last
}

// HasTXT reports whether at least one non-empty TXT value is stored for the domain
func (d DomainInfo) HasTXT() bool {
	for _, t := range d.TXT {
		if t.Value != "" {
			return true
		}
	}
	return false
}

// DomainActivity is a compact per-subdomain summary used for reporting
type DomainActivity struct {
	Subdomain string
	// LastUpdate is the unix timestamp of the most recent TXT update, 0 if never updated
	LastUpdate int64
	// HasTXT reports whether at least one non-empty TXT value is stored
	HasTXT bool
}
