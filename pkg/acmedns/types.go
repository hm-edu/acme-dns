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

// AllowedFrom checks if an IP address is within the allowed ranges
func (a ACMETxt) AllowedFrom(ip string) bool {
	remoteIP := net.ParseIP(ip)
	if len(a.AllowFrom.ValidEntries()) == 0 {
		return true
	}
	log.WithFields(log.Fields{"ip": remoteIP}).Debug("Checking if update is permitted from IP")
	for _, v := range a.AllowFrom.ValidEntries() {
		_, vnet, _ := net.ParseCIDR(v)
		if vnet.Contains(remoteIP) {
			return true
		}
	}
	return false
}

// AllowedFromList checks if any IP in the list is within the allowed ranges
func (a ACMETxt) AllowedFromList(ips []string) bool {
	if len(ips) == 0 {
		return a.AllowedFrom("")
	}
	for _, v := range ips {
		if a.AllowedFrom(v) {
			return true
		}
	}
	return false
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
