package acmedns

import (
	"regexp"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// GetValidUsername parses and validates a UUID username string
func GetValidUsername(u string) (uuid.UUID, error) {
	uname, err := uuid.Parse(u)
	if err != nil {
		return uuid.UUID{}, err
	}
	return uname, nil
}

// ValidKey checks that an API key is the correct length and contains only valid characters
func ValidKey(k string) bool {
	kn := SanitizeString(k)
	if utf8.RuneCountInString(k) == 40 && utf8.RuneCountInString(kn) == 40 {
		return true
	}
	return false
}

// ValidSubdomain checks that a subdomain is a valid DNS label
func ValidSubdomain(s string) bool {
	RegExp := regexp.MustCompile("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
	return RegExp.MatchString(s)
}

// ValidTXT checks that a TXT value is the correct length and contains only valid characters
func ValidTXT(s string) bool {
	sn := SanitizeString(s)
	if utf8.RuneCountInString(s) == 43 && utf8.RuneCountInString(sn) == 43 {
		return true
	}
	return false
}

// CorrectPassword checks that a plaintext password matches a bcrypt hash
func CorrectPassword(pw string, hash string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)); err == nil {
		return true
	}
	return false
}
