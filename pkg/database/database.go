package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hm-edu/acme-dns/pkg/acmedns"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// DBVersion shows the database version this code uses
var DBVersion = 1

var acmeTable = `
	CREATE TABLE IF NOT EXISTS acmedns(
		Name TEXT,
		Value TEXT
	);`

var userTable = `
	CREATE TABLE IF NOT EXISTS records(
        Username TEXT UNIQUE NOT NULL PRIMARY KEY,
        Password TEXT UNIQUE NOT NULL,
        Subdomain TEXT UNIQUE NOT NULL,
		AllowFrom TEXT
    );`

var txtTable = `
    CREATE TABLE IF NOT EXISTS txt(
		Subdomain TEXT NOT NULL,
		Value   TEXT NOT NULL DEFAULT '',
		LastUpdate INT
	);`

var txtTablePG = `
    CREATE TABLE IF NOT EXISTS txt(
		rowid SERIAL,
		Subdomain TEXT NOT NULL,
		Value   TEXT NOT NULL DEFAULT '',
		LastUpdate INT
	);`

// AcmeDB implements acmedns.Database using SQL
type AcmeDB struct {
	sync.Mutex
	DB     *sql.DB
	engine string
}

// New returns a new empty AcmeDB
func New() *AcmeDB {
	return &AcmeDB{}
}

// getSQLiteStmt replaces PostgreSQL placeholders with SQLite variant
func getSQLiteStmt(s string) string {
	re, _ := regexp.Compile(`\$[0-9]`)
	return re.ReplaceAllString(s, "?")
}

// Init opens the database and runs migrations
func (d *AcmeDB) Init(engine string, connection string) error {
	d.Lock()
	defer d.Unlock()
	d.engine = engine
	db, err := sql.Open(engine, connection)
	if err != nil {
		return err
	}
	d.DB = db

	var versionString string
	_ = d.DB.QueryRow("SELECT Value FROM acmedns WHERE Name='db_version'").Scan(&versionString)
	if versionString == "" {
		versionString = "0"
	}
	_, err = d.DB.Exec(acmeTable)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Error creating acmedns table")
	}
	_, err = d.DB.Exec(userTable)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Error creating records table")
	}
	if d.engine == "sqlite3" {
		_, err = d.DB.Exec(txtTable)
	} else {
		_, err = d.DB.Exec(txtTablePG)
	}
	if err == nil {
		err = d.checkDBUpgrades(versionString)
	}
	if err == nil {
		if versionString == "0" {
			insversion := fmt.Sprintf("INSERT INTO acmedns (Name, Value) values('db_version', '%d')", DBVersion)
			_, err = db.Exec(insversion)
		}
	}
	return err
}

func (d *AcmeDB) checkDBUpgrades(versionString string) error {
	version := 0
	_, err := fmt.Sscan(versionString, &version)
	if err != nil {
		return err
	}
	if version != DBVersion {
		return d.handleDBUpgrades(version)
	}
	return nil
}

func (d *AcmeDB) handleDBUpgrades(version int) error {
	if version == 0 {
		return d.handleDBUpgradeTo1()
	}
	return nil
}

func (d *AcmeDB) handleDBUpgradeTo1() error {
	var err error
	var subdomains []string
	rows, err := d.DB.Query("SELECT Subdomain FROM records")
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Error in DB upgrade")
		return err
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)
	for rows.Next() {
		var subdomain string
		err = rows.Scan(&subdomain)
		if err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Error("Error in DB upgrade while reading values")
			return err
		}
		subdomains = append(subdomains, subdomain)
	}
	err = rows.Err()
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Error in DB upgrade while inserting values")
		return err
	}
	tx, err := d.DB.Begin()
	defer func() {
		if err != nil {
			_ = tx.Rollback()
			return
		}
		_ = tx.Commit()
	}()
	_, _ = tx.Exec("DELETE FROM txt")
	for _, subdomain := range subdomains {
		if subdomain != "" {
			err = d.newTXTValuesInTransaction(tx, subdomain)
			if err != nil {
				log.WithFields(log.Fields{"error": err.Error()}).Error("Error in DB upgrade while inserting values")
				return err
			}
		}
	}
	if d.engine != "sqlite3" {
		_, _ = tx.Exec("ALTER TABLE records DROP COLUMN IF EXISTS Value")
		_, _ = tx.Exec("ALTER TABLE records DROP COLUMN IF EXISTS LastActive")
	}
	_, err = tx.Exec("UPDATE acmedns SET Value='1' WHERE Name='db_version'")
	return err
}

func (d *AcmeDB) newTXTValuesInTransaction(tx *sql.Tx, subdomain string) error {
	var err error
	instr := fmt.Sprintf("INSERT INTO txt (Subdomain, LastUpdate) values('%s', 0)", subdomain)
	_, _ = tx.Exec(instr)
	_, _ = tx.Exec(instr)
	return err
}

// Register creates a new user record with the provided CIDR allowlist
func (d *AcmeDB) Register(afrom acmedns.CIDRSlice) (acmedns.ACMETxt, error) {
	d.Lock()
	defer d.Unlock()
	var err error
	tx, err := d.DB.Begin()
	defer func() {
		if err != nil {
			_ = tx.Rollback()
			return
		}
		_ = tx.Commit()
	}()
	a := acmedns.NewACMETxt()
	a.AllowFrom = acmedns.CIDRSlice(afrom.ValidEntries())
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(a.Password), 10)
	regSQL := `
    INSERT INTO records(
        Username,
        Password,
        Subdomain,
		AllowFrom) 
        values($1, $2, $3, $4)`
	if d.engine == "sqlite3" {
		regSQL = getSQLiteStmt(regSQL)
	}
	sm, err := tx.Prepare(regSQL)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Database error in prepare")
		return a, errors.New("SQL error")
	}
	defer func(sm *sql.Stmt) {
		_ = sm.Close()
	}(sm)
	_, err = sm.Exec(a.Username.String(), passwordHash, a.Subdomain, a.AllowFrom.JSON())
	if err == nil {
		err = d.newTXTValuesInTransaction(tx, a.Subdomain)
	}
	return a, err
}

// GetByUsername retrieves a user record by UUID
func (d *AcmeDB) GetByUsername(u uuid.UUID) (acmedns.ACMETxt, error) {
	d.Lock()
	defer d.Unlock()
	var results []acmedns.ACMETxt
	getSQL := `
	SELECT Username, Password, Subdomain, AllowFrom
	FROM records
	WHERE Username=$1 LIMIT 1
	`
	if d.engine == "sqlite3" {
		getSQL = getSQLiteStmt(getSQL)
	}

	sm, err := d.DB.Prepare(getSQL)
	if err != nil {
		return acmedns.ACMETxt{}, err
	}
	defer func(sm *sql.Stmt) {
		_ = sm.Close()
	}(sm)
	rows, err := sm.Query(u.String())
	if err != nil {
		return acmedns.ACMETxt{}, err
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	for rows.Next() {
		txt, err := getModelFromRow(rows)
		if err != nil {
			return acmedns.ACMETxt{}, err
		}
		results = append(results, txt)
	}
	if len(results) > 0 {
		return results[0], nil
	}
	return acmedns.ACMETxt{}, errors.New("no user")
}

// GetTXTForDomain retrieves TXT records for a subdomain
func (d *AcmeDB) GetTXTForDomain(domain string) ([]string, error) {
	d.Lock()
	defer d.Unlock()
	domain = acmedns.SanitizeString(domain)
	var txts []string
	getSQL := `
	SELECT Value FROM txt WHERE Subdomain=$1 LIMIT 2
	`
	if d.engine == "sqlite3" {
		getSQL = getSQLiteStmt(getSQL)
	}

	sm, err := d.DB.Prepare(getSQL)
	if err != nil {
		return txts, err
	}
	defer func(sm *sql.Stmt) {
		_ = sm.Close()
	}(sm)
	rows, err := sm.Query(domain)
	if err != nil {
		return txts, err
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	for rows.Next() {
		var rtxt string
		err = rows.Scan(&rtxt)
		if err != nil {
			return txts, err
		}
		txts = append(txts, rtxt)
	}
	return txts, nil
}

// Update updates the TXT value for a subdomain
func (d *AcmeDB) Update(a acmedns.ACMETxtPost) error {
	d.Lock()
	defer d.Unlock()
	var err error
	timenow := time.Now().Unix()

	updSQL := `
	UPDATE txt SET Value=$1, LastUpdate=$2
	WHERE rowid=(
		SELECT rowid FROM txt WHERE Subdomain=$3 ORDER BY LastUpdate LIMIT 1)
	`
	if d.engine == "sqlite3" {
		updSQL = getSQLiteStmt(updSQL)
	}

	sm, err := d.DB.Prepare(updSQL)
	if err != nil {
		return err
	}
	defer func(sm *sql.Stmt) {
		_ = sm.Close()
	}(sm)
	_, err = sm.Exec(a.Value, timenow, a.Subdomain)
	if err != nil {
		return err
	}
	return nil
}

func getModelFromRow(r *sql.Rows) (acmedns.ACMETxt, error) {
	txt := acmedns.ACMETxt{}
	afrom := ""
	err := r.Scan(
		&txt.Username,
		&txt.Password,
		&txt.Subdomain,
		&afrom)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Row scan error")
	}

	cslice := acmedns.CIDRSlice{}
	err = json.Unmarshal([]byte(afrom), &cslice)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("JSON unmarshall error")
	}
	txt.AllowFrom = cslice
	return txt, err
}

// Close closes the database connection
func (d *AcmeDB) Close() {
	_ = d.DB.Close()
}

// GetBackend returns the underlying sql.DB
func (d *AcmeDB) GetBackend() *sql.DB {
	return d.DB
}

// SetBackend replaces the underlying sql.DB
func (d *AcmeDB) SetBackend(backend *sql.DB) {
	d.DB = backend
}
