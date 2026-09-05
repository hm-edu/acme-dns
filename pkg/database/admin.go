package database

import (
	"database/sql"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/hm-edu/acme-dns/pkg/acmedns"
	log "github.com/sirupsen/logrus"
)

var listDomainsSQL = `
	SELECT r.Username, r.Subdomain, r.AllowFrom, t.Value, t.LastUpdate
	FROM (SELECT Username, Subdomain, AllowFrom FROM records ORDER BY Subdomain LIMIT $1 OFFSET $2) r
	LEFT JOIN txt t ON t.Subdomain = r.Subdomain
	ORDER BY r.Subdomain, t.LastUpdate DESC, t.Value`

var getDomainSQL = `
	SELECT r.Username, r.Subdomain, r.AllowFrom, t.Value, t.LastUpdate
	FROM records r
	LEFT JOIN txt t ON t.Subdomain = r.Subdomain
	WHERE r.Subdomain = $1
	ORDER BY t.LastUpdate DESC, t.Value`

var domainActivitySQL = `
	SELECT r.Subdomain,
		MAX(COALESCE(t.LastUpdate, 0)),
		MAX(CASE WHEN COALESCE(t.Value, '') <> '' THEN 1 ELSE 0 END)
	FROM records r
	LEFT JOIN txt t ON t.Subdomain = r.Subdomain
	GROUP BY r.Subdomain
	ORDER BY r.Subdomain`

// CountDomains returns the number of registered subdomains
func (d *AcmeDB) CountDomains() (int, error) {
	d.Lock()
	defer d.Unlock()
	var count int
	err := d.DB.QueryRow("SELECT COUNT(*) FROM records").Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// ListDomains returns registered subdomains ordered by subdomain, starting at
// offset and returning at most limit entries
func (d *AcmeDB) ListDomains(limit int, offset int) ([]acmedns.DomainInfo, error) {
	d.Lock()
	defer d.Unlock()
	return d.queryDomainInfos(listDomainsSQL, limit, offset)
}

// GetDomain returns the details of a single registered subdomain
func (d *AcmeDB) GetDomain(subdomain string) (acmedns.DomainInfo, error) {
	d.Lock()
	defer d.Unlock()
	infos, err := d.queryDomainInfos(getDomainSQL, acmedns.SanitizeString(subdomain))
	if err != nil {
		return acmedns.DomainInfo{}, err
	}
	if len(infos) == 0 {
		return acmedns.DomainInfo{}, acmedns.ErrDomainNotFound
	}
	return infos[0], nil
}

// GetDomainActivity returns a compact summary of every registered subdomain
func (d *AcmeDB) GetDomainActivity() ([]acmedns.DomainActivity, error) {
	d.Lock()
	defer d.Unlock()
	rows, err := d.DB.Query(domainActivitySQL)
	if err != nil {
		return nil, err
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	result := []acmedns.DomainActivity{}
	for rows.Next() {
		var subdomain string
		var lastUpdate sql.NullInt64
		var hasTXT sql.NullInt64
		if err := rows.Scan(&subdomain, &lastUpdate, &hasTXT); err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Error("Row scan error")
			return nil, err
		}
		result = append(result, acmedns.DomainActivity{
			Subdomain:  subdomain,
			LastUpdate: lastUpdate.Int64,
			HasTXT:     hasTXT.Int64 > 0,
		})
	}
	return result, rows.Err()
}

// queryDomainInfos runs a query selecting Username, Subdomain, AllowFrom, Value
// and LastUpdate and folds
// the (up to two) txt rows per subdomain into a single DomainInfo. Rows have to
// be ordered by subdomain.
func (d *AcmeDB) queryDomainInfos(query string, args ...interface{}) ([]acmedns.DomainInfo, error) {
	if d.engine == "sqlite3" {
		query = getSQLiteStmt(query)
	}
	rows, err := d.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	result := []acmedns.DomainInfo{}
	for rows.Next() {
		var username, subdomain string
		var allowFrom, value sql.NullString
		var lastUpdate sql.NullInt64
		if err := rows.Scan(&username, &subdomain, &allowFrom, &value, &lastUpdate); err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Error("Row scan error")
			return nil, err
		}
		if len(result) == 0 || result[len(result)-1].Subdomain != subdomain {
			uid, err := uuid.Parse(username)
			if err != nil {
				log.WithFields(log.Fields{"error": err.Error(), "username": username}).Error("Invalid username in database")
				return nil, err
			}
			result = append(result, acmedns.DomainInfo{
				Username:  uid,
				Subdomain: subdomain,
				AllowFrom: parseAllowFrom(allowFrom.String),
				TXT:       []acmedns.TXTRecord{},
			})
		}
		if value.Valid {
			current := &result[len(result)-1]
			current.TXT = append(current.TXT, acmedns.TXTRecord{Value: value.String, LastUpdate: lastUpdate.Int64})
		}
	}
	return result, rows.Err()
}

func parseAllowFrom(raw string) acmedns.CIDRSlice {
	cslice := acmedns.CIDRSlice{}
	if raw == "" {
		return cslice
	}
	if err := json.Unmarshal([]byte(raw), &cslice); err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("JSON unmarshall error")
		return acmedns.CIDRSlice{}
	}
	return cslice
}

// DeleteDomain removes a registered subdomain and its TXT records
func (d *AcmeDB) DeleteDomain(subdomain string) (err error) {
	d.Lock()
	defer d.Unlock()
	subdomain = acmedns.SanitizeString(subdomain)
	tx, err := d.DB.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	delRecord := "DELETE FROM records WHERE Subdomain=$1"
	delTXT := "DELETE FROM txt WHERE Subdomain=$1"
	if d.engine == "sqlite3" {
		delRecord = getSQLiteStmt(delRecord)
		delTXT = getSQLiteStmt(delTXT)
	}
	res, err := tx.Exec(delRecord, subdomain)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		err = acmedns.ErrDomainNotFound
		return err
	}
	if _, err = tx.Exec(delTXT, subdomain); err != nil {
		return err
	}
	err = tx.Commit()
	return err
}
