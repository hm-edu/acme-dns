package acmedns

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// JsonError returns a JSON-encoded error message
func JsonError(message string) []byte {
	return []byte(fmt.Sprintf("{\"error\": \"%s\"}", message))
}

// SanitizeString removes characters not in the URL-safe base64 alphabet
func SanitizeString(s string) string {
	re, _ := regexp.Compile(`[^A-Za-z\-\_0-9]+`)
	return re.ReplaceAllString(s, "")
}

// SanitizeIPv6addr removes brackets from IPv6 addresses
func SanitizeIPv6addr(s string) string {
	re, _ := regexp.Compile(`[\[\]]+`)
	return re.ReplaceAllString(s, "")
}

// GeneratePassword generates a random password of the given length
func GeneratePassword(length int) string {
	ret := make([]byte, length)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-_"
	alphalen := big.NewInt(int64(len(alphabet)))
	for i := 0; i < length; i++ {
		c, _ := rand.Int(rand.Reader, alphalen)
		r := int(c.Int64())
		ret[i] = alphabet[r]
	}
	return string(ret)
}

// SanitizeDomainQuestion extracts the subdomain label from a DNS question
func SanitizeDomainQuestion(d string) string {
	dom := strings.ToLower(d)
	firstDot := strings.Index(d, ".")
	if firstDot > 0 {
		dom = dom[0:firstDot]
	}
	return dom
}

// GetIPListFromHeader parses a comma-separated list of IPs from a header value
func GetIPListFromHeader(header string) []string {
	iplist := []string{}
	for _, v := range strings.Split(header, ",") {
		if len(v) > 0 {
			iplist = append(iplist, strings.TrimSpace(v))
		}
	}
	return iplist
}
