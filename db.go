package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// DBVersion shows the database version this code uses. This is used for update checks.
var DBVersion = 2

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

var dnsRecordsTable = `
	CREATE TABLE IF NOT EXISTS dns_records (
		id      TEXT PRIMARY KEY,
		name    TEXT NOT NULL,
		type    TEXT NOT NULL,
		value   TEXT NOT NULL,
		ttl     INTEGER NOT NULL DEFAULT 300,
		created INTEGER NOT NULL
	);`

var dnsRecordsIndex = `
	CREATE INDEX IF NOT EXISTS idx_dns_records_name_type ON dns_records (name, type);`

// getSQLiteStmt replaces all PostgreSQL prepared statement placeholders (eg. $1, $2) with SQLite variant "?"
func getSQLiteStmt(s string) string {
	re, _ := regexp.Compile(`\$[0-9]`)
	return re.ReplaceAllString(s, "?")
}

func (d *acmedb) Init(engine string, connection string) error {
	d.Lock()
	defer d.Unlock()

	if engine == "sqlite3" {
		engine = "sqlite"
	}

	db, err := sql.Open(engine, connection)
	if err != nil {
		return err
	}
	d.DB = db
	// Check version first to try to catch old versions without version string
	var versionString string
	_ = d.DB.QueryRow("SELECT Value FROM acmedns WHERE Name='db_version'").Scan(&versionString)
	if versionString == "" {
		versionString = "0"
	}
	_, _ = d.DB.Exec(acmeTable)
	_, _ = d.DB.Exec(userTable)
	if Config.Database.Engine == "sqlite3" {
		_, _ = d.DB.Exec(txtTable)
	} else {
		_, _ = d.DB.Exec(txtTablePG)
	}
	_, _ = d.DB.Exec(dnsRecordsTable)
	_, _ = d.DB.Exec(dnsRecordsIndex)
	// If everything is fine, handle db upgrade tasks
	if err == nil {
		err = d.checkDBUpgrades(versionString)
	}
	if err == nil {
		if versionString == "0" {
		// No errors so we should now be in the current version
			insversion := fmt.Sprintf("INSERT INTO acmedns (Name, Value) values('db_version', '%d')", DBVersion)
			_, err = db.Exec(insversion)
		}
	}
	return err
}

func (d *acmedb) checkDBUpgrades(versionString string) error {
	var err error
	version, err := strconv.Atoi(versionString)
	if err != nil {
		return err
	}
	if version != DBVersion {
		return d.handleDBUpgrades(version)
	}
	return nil

}

func (d *acmedb) handleDBUpgrades(version int) error {
	for version < DBVersion {
		var err error
		switch version {
		case 0:
			err = d.handleDBUpgradeTo1()
		case 1:
			err = d.handleDBUpgradeTo2()
		default:
			return nil
		}
		if err != nil {
			return err
		}
		version++
	}
	return nil
}

func (d *acmedb) handleDBUpgradeTo1() error {
	var err error
	var subdomains []string
	rows, err := d.DB.Query("SELECT Subdomain FROM records")
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Error in DB upgrade")
		return err
	}
	defer closeRows(rows)
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
	// Rollback if errored, commit if not
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
			// Insert two rows for each subdomain to txt table
			err = d.NewTXTValuesInTransaction(tx, subdomain)
			if err != nil {
				log.WithFields(log.Fields{"error": err.Error()}).Error("Error in DB upgrade while inserting values")
				return err
			}
		}
	}
	// SQLite doesn't support dropping columns
	if Config.Database.Engine != "sqlite3" {
		_, _ = tx.Exec("ALTER TABLE records DROP COLUMN IF EXISTS Value")
		_, _ = tx.Exec("ALTER TABLE records DROP COLUMN IF EXISTS LastActive")
	}
	_, err = tx.Exec("UPDATE acmedns SET Value='1' WHERE Name='db_version'")
	return err
}

func (d *acmedb) handleDBUpgradeTo2() error {
	_, err := d.DB.Exec("UPDATE acmedns SET Value='2' WHERE Name='db_version'")
	return err
}

// Create two rows for subdomain to the txt table
func (d *acmedb) NewTXTValuesInTransaction(tx *sql.Tx, subdomain string) error {
	var err error
	instr := fmt.Sprintf("INSERT INTO txt (Subdomain, LastUpdate) values('%s', 0)", subdomain)
	_, _ = tx.Exec(instr)
	_, _ = tx.Exec(instr)
	return err
}

func (d *acmedb) Register(afrom cidrslice) (ACMETxt, error) {
	d.Lock()
	defer d.Unlock()
	var err error
	tx, err := d.DB.Begin()
	// Rollback if errored, commit if not
	defer func() {
		if err != nil {
			_ = tx.Rollback()
			return
		}
		_ = tx.Commit()
	}()
	a := newACMETxt()
	a.AllowFrom = afrom.ValidEntries()
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(a.Password), 10)
	regSQL := `
    INSERT INTO records(
        Username,
        Password,
        Subdomain,
		AllowFrom) 
        values($1, $2, $3, $4)`
	if Config.Database.Engine == "sqlite3" {
		regSQL = getSQLiteStmt(regSQL)
	}
	sm, err := tx.Prepare(regSQL)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Database error in prepare")
		return a, errors.New("SQL error")
	}
	defer closeStatement(sm)
	_, err = sm.Exec(a.Username.String(), passwordHash, a.Subdomain, a.AllowFrom.JSON())
	if err == nil {
		err = d.NewTXTValuesInTransaction(tx, a.Subdomain)
	}
	return a, err
}

func (d *acmedb) GetByUsername(u uuid.UUID) (ACMETxt, error) {
	d.Lock()
	defer d.Unlock()
	var results []ACMETxt
	getSQL := `
	SELECT Username, Password, Subdomain, AllowFrom
	FROM records
	WHERE Username=$1 LIMIT 1
	`
	if Config.Database.Engine == "sqlite3" {
		getSQL = getSQLiteStmt(getSQL)
	}

	sm, err := d.DB.Prepare(getSQL)
	if err != nil {
		return ACMETxt{}, err
	}
	defer closeStatement(sm)
	rows, err := sm.Query(u.String())
	if err != nil {
		return ACMETxt{}, err
	}
	defer closeRows(rows)

	// It will only be one row though
	for rows.Next() {
		txt, err := getModelFromRow(rows)
		if err != nil {
			return ACMETxt{}, err
		}
		results = append(results, txt)
	}
	if len(results) > 0 {
		return results[0], nil
	}
	return ACMETxt{}, errors.New("no user")
}

func (d *acmedb) GetTXTForDomain(domain string) ([]string, error) {
	d.Lock()
	defer d.Unlock()
	domain = sanitizeString(domain)
	var txts []string
	getSQL := `
	SELECT Value FROM txt WHERE Subdomain=$1 LIMIT 2
	`
	if Config.Database.Engine == "sqlite3" {
		getSQL = getSQLiteStmt(getSQL)
	}

	sm, err := d.DB.Prepare(getSQL)
	if err != nil {
		return txts, err
	}
	defer closeStatement(sm)
	rows, err := sm.Query(domain)
	if err != nil {
		return txts, err
	}
	defer closeRows(rows)
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

func (d *acmedb) Update(a ACMETxtPost) error {
	d.Lock()
	defer d.Unlock()
	var err error
	// Data in a is already sanitized
	timenow := time.Now().Unix()

	updSQL := `
	UPDATE txt SET Value=$1, LastUpdate=$2
	WHERE rowid=(
		SELECT rowid FROM txt WHERE Subdomain=$3 ORDER BY LastUpdate LIMIT 1)
	`
	if Config.Database.Engine == "sqlite3" {
		updSQL = getSQLiteStmt(updSQL)
	}

	sm, err := d.DB.Prepare(updSQL)
	if err != nil {
		return err
	}
	defer closeStatement(sm)
	_, err = sm.Exec(a.Value, timenow, a.Subdomain)
	if err != nil {
		return err
	}
	return nil
}

func (d *acmedb) CreateRecord(rec DNSRecord) error {
	d.Lock()
	defer d.Unlock()
	stmt := `INSERT INTO dns_records (id, name, type, value, ttl, created) VALUES ($1, $2, $3, $4, $5, $6)`
	if Config.Database.Engine == "sqlite3" {
		stmt = getSQLiteStmt(stmt)
	}
	_, err := d.DB.Exec(stmt, rec.ID, rec.Name, rec.Type, rec.Value, rec.TTL, rec.Created)
	return err
}

func (d *acmedb) GetRecord(id string) (DNSRecord, error) {
	d.Lock()
	defer d.Unlock()
	q := `SELECT id, name, type, value, ttl, created FROM dns_records WHERE id = $1`
	if Config.Database.Engine == "sqlite3" {
		q = getSQLiteStmt(q)
	}
	var r DNSRecord
	err := d.DB.QueryRow(q, id).Scan(&r.ID, &r.Name, &r.Type, &r.Value, &r.TTL, &r.Created)
	if err == sql.ErrNoRows {
		return DNSRecord{}, sql.ErrNoRows
	}
	return r, err
}

func (d *acmedb) ListRecords(filterType, filterName string) ([]DNSRecord, error) {
	d.Lock()
	defer d.Unlock()
	q := `SELECT id, name, type, value, ttl, created FROM dns_records WHERE ($1 = '' OR type = $2) AND ($3 = '' OR name = $4)`
	if Config.Database.Engine == "sqlite3" {
		q = getSQLiteStmt(q)
	}
	rows, err := d.DB.Query(q, filterType, filterType, filterName, filterName)
	if err != nil {
		return nil, err
	}
	defer closeRows(rows)
	var records []DNSRecord
	for rows.Next() {
		var r DNSRecord
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.Value, &r.TTL, &r.Created); err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if records == nil {
		records = []DNSRecord{}
	}
	return records, nil
}

func (d *acmedb) UpdateRecord(rec DNSRecord) error {
	d.Lock()
	defer d.Unlock()
	stmt := `UPDATE dns_records SET name=$1, type=$2, value=$3, ttl=$4 WHERE id=$5`
	if Config.Database.Engine == "sqlite3" {
		stmt = getSQLiteStmt(stmt)
	}
	result, err := d.DB.Exec(stmt, rec.Name, rec.Type, rec.Value, rec.TTL, rec.ID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (d *acmedb) DeleteRecord(id string) error {
	d.Lock()
	defer d.Unlock()
	stmt := `DELETE FROM dns_records WHERE id=$1`
	if Config.Database.Engine == "sqlite3" {
		stmt = getSQLiteStmt(stmt)
	}
	result, err := d.DB.Exec(stmt, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func getModelFromRow(r *sql.Rows) (ACMETxt, error) {
	txt := ACMETxt{}
	afrom := ""
	err := r.Scan(
		&txt.Username,
		&txt.Password,
		&txt.Subdomain,
		&afrom)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Row scan error")
	}

	cSlice := cidrslice{}
	err = json.Unmarshal([]byte(afrom), &cSlice)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("JSON unmarshall error")
	}
	txt.AllowFrom = cSlice
	return txt, err
}

func (d *acmedb) Close() {
	_ = d.DB.Close()
}

func (d *acmedb) GetBackend() *sql.DB {
	return d.DB
}

func (d *acmedb) SetBackend(backend *sql.DB) {
	d.DB = backend
}

func closeStatement(sm *sql.Stmt) {
	smErr := sm.Close()
	if smErr != nil {
		panic(smErr)
	}
}

func closeRows(rows *sql.Rows) {
	rsErr := rows.Close()
	if rsErr != nil {
		panic(rsErr)
	}
}
