package main

import (
	"net"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func getValidUsername(u string) (uuid.UUID, error) {
	uname, err := uuid.Parse(u)
	if err != nil {
		return uuid.UUID{}, err
	}
	return uname, nil
}

func validKey(k string) bool {
	kn := sanitizeString(k)
	if utf8.RuneCountInString(k) == 40 && utf8.RuneCountInString(kn) == 40 {
		// Correct length and all chars valid
		return true
	}
	return false
}

func validSubdomain(s string) bool {
	// URL safe base64 alphabet without padding as defined in ACME
	RegExp := regexp.MustCompile("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
	return RegExp.MatchString(s)
}

func validTXT(s string) bool {
	sn := sanitizeString(s)
	if utf8.RuneCountInString(s) == 43 && utf8.RuneCountInString(sn) == 43 {
		// 43 chars is the current LE auth key size, but not limited / defined by ACME
		return true
	}
	return false
}

func correctPassword(pw string, hash string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)); err == nil {
		return true
	}
	return false
}

func validRecordType(typ string) bool {
	switch typ {
	case "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA", "PTR":
		return true
	}
	return false
}

func validTTL(ttl int) bool {
	return ttl >= 1 && ttl <= 86400
}

func validRecordValue(rtype, value string) bool {
	if value == "" {
		return false
	}
	switch rtype {
	case "A":
		ip := net.ParseIP(value)
		return ip != nil && ip.To4() != nil && !strings.Contains(value, ":")
	case "AAAA":
		ip := net.ParseIP(value)
		return ip != nil && ip.To4() == nil
	case "CNAME", "MX", "NS", "PTR", "SRV", "TXT", "CAA":
		return true // non-empty check handled above; structural validation deferred to dns.NewRR
	}
	return false
}
