package acmedns

import (
	"database/sql"
	"errors"

	"github.com/google/uuid"
)

// ErrDomainNotFound is returned when a subdomain is not registered
var ErrDomainNotFound = errors.New("domain not found")

// Database is the interface for acme-dns database operations
type Database interface {
	Init(string, string) error
	Register(CIDRSlice) (ACMETxt, error)
	GetByUsername(uuid.UUID) (ACMETxt, error)
	GetTXTForDomain(string) ([]string, error)
	Update(ACMETxtPost) error
	// CountDomains returns the number of registered subdomains
	CountDomains() (int, error)
	// ListDomains returns registered subdomains ordered by subdomain, starting at offset and returning at most limit entries
	ListDomains(limit int, offset int) ([]DomainInfo, error)
	// GetDomain returns the details of a single registered subdomain, ErrDomainNotFound if it does not exist
	GetDomain(string) (DomainInfo, error)
	// GetDomainActivity returns a compact summary of every registered subdomain for reporting
	GetDomainActivity() ([]DomainActivity, error)
	// DeleteDomain removes a registered subdomain including its TXT records, ErrDomainNotFound if it does not exist
	DeleteDomain(string) error
	GetBackend() *sql.DB
	SetBackend(*sql.DB)
	Close()
	Lock()
	Unlock()
}
