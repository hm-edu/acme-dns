package acmedns

import (
	"database/sql"

	"github.com/google/uuid"
)

// Database is the interface for acme-dns database operations
type Database interface {
	Init(string, string) error
	Register(CIDRSlice) (ACMETxt, error)
	GetByUsername(uuid.UUID) (ACMETxt, error)
	GetTXTForDomain(string) ([]string, error)
	Update(ACMETxtPost) error
	GetBackend() *sql.DB
	SetBackend(*sql.DB)
	Close()
	Lock()
	Unlock()
}
