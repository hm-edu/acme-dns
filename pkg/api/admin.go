package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/hm-edu/acme-dns/pkg/acmedns"
	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
)

const (
	// AdminDefaultLimit is the page size used by the domain listing when no limit is given
	AdminDefaultLimit = 100
	// AdminMaxLimit is the largest page size accepted by the domain listing
	AdminMaxLimit = 1000
	// AdminRecentUpdates is the number of most recently updated domains included in the report
	AdminRecentUpdates = 10
)

// AdminTXTRecord is one stored TXT value of a domain
type AdminTXTRecord struct {
	Value      string     `json:"txt"`
	LastUpdate *time.Time `json:"last_update"`
}

// AdminDomain is the admin API representation of a registered subdomain
type AdminDomain struct {
	Username   string           `json:"username"`
	Subdomain  string           `json:"subdomain"`
	Fulldomain string           `json:"fulldomain"`
	Allowfrom  []string         `json:"allowfrom"`
	TXTRecords []AdminTXTRecord `json:"txt_records"`
	HasTXT     bool             `json:"has_txt"`
	LastUpdate *time.Time       `json:"last_update"`
}

// AdminDomainList is the response body of the domain listing
type AdminDomainList struct {
	Total   int           `json:"total"`
	Limit   int           `json:"limit"`
	Offset  int           `json:"offset"`
	Domains []AdminDomain `json:"domains"`
}

// AdminReportCounts holds the aggregated domain statistics of the report
type AdminReportCounts struct {
	Total          int `json:"total"`
	WithTXT        int `json:"with_txt"`
	NeverUpdated   int `json:"never_updated"`
	UpdatedLast24h int `json:"updated_last_24h"`
	UpdatedLast7d  int `json:"updated_last_7d"`
	UpdatedLast30d int `json:"updated_last_30d"`
	UpdatedLast90d int `json:"updated_last_90d"`
	// Stale counts domains that have been updated at least once, but not within the last 90 days
	Stale int `json:"stale"`
}

// AdminRecentUpdate is an entry of the recently updated domains list in the report
type AdminRecentUpdate struct {
	Subdomain  string    `json:"subdomain"`
	Fulldomain string    `json:"fulldomain"`
	LastUpdate time.Time `json:"last_update"`
}

// AdminReport is the response body of the report endpoint
type AdminReport struct {
	GeneratedAt     time.Time           `json:"generated_at"`
	Domain          string              `json:"domain"`
	DatabaseEngine  string              `json:"database_engine"`
	Domains         AdminReportCounts   `json:"domains"`
	RecentlyUpdated []AdminRecentUpdate `json:"recently_updated"`
}

// AdminListDomains handles GET /admin/domains
func (a *API) AdminListDomains(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	limit, offset, err := parsePagination(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_query_parameter")
		return
	}
	total, err := a.DB.CountDomains()
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Error while counting domains")
		writeJSONError(w, http.StatusInternalServerError, "db_error")
		return
	}
	infos, err := a.DB.ListDomains(limit, offset)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Error while listing domains")
		writeJSONError(w, http.StatusInternalServerError, "db_error")
		return
	}
	resp := AdminDomainList{Total: total, Limit: limit, Offset: offset, Domains: make([]AdminDomain, 0, len(infos))}
	for _, info := range infos {
		resp.Domains = append(resp.Domains, a.adminDomain(info))
	}
	writeJSON(w, http.StatusOK, resp)
}

// AdminGetDomain handles GET /admin/domains/:subdomain
func (a *API) AdminGetDomain(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	subdomain := p.ByName("subdomain")
	if !acmedns.ValidSubdomain(subdomain) {
		writeJSONError(w, http.StatusBadRequest, "bad_subdomain")
		return
	}
	info, err := a.DB.GetDomain(subdomain)
	if errors.Is(err, acmedns.ErrDomainNotFound) {
		writeJSONError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error(), "subdomain": subdomain}).Error("Error while fetching domain")
		writeJSONError(w, http.StatusInternalServerError, "db_error")
		return
	}
	writeJSON(w, http.StatusOK, a.adminDomain(info))
}

// AdminReport handles GET /admin/report
func (a *API) AdminReport(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	activity, err := a.DB.GetDomainActivity()
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Error while gathering domain activity")
		writeJSONError(w, http.StatusInternalServerError, "db_error")
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	counts, recent := BuildReport(activity, now, AdminRecentUpdates)
	resp := AdminReport{
		GeneratedAt:     now,
		Domain:          a.Config.General.Domain,
		DatabaseEngine:  a.Config.Database.Engine,
		Domains:         counts,
		RecentlyUpdated: make([]AdminRecentUpdate, 0, len(recent)),
	}
	for _, act := range recent {
		resp.RecentlyUpdated = append(resp.RecentlyUpdated, AdminRecentUpdate{
			Subdomain:  act.Subdomain,
			Fulldomain: a.fulldomain(act.Subdomain),
			LastUpdate: time.Unix(act.LastUpdate, 0).UTC(),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// BuildReport aggregates the per-domain activity into report counters relative
// to now and returns the recentLimit most recently updated domains.
func BuildReport(activity []acmedns.DomainActivity, now time.Time, recentLimit int) (AdminReportCounts, []acmedns.DomainActivity) {
	counts := AdminReportCounts{Total: len(activity)}
	day := 24 * time.Hour
	updated := make([]acmedns.DomainActivity, 0, len(activity))
	for _, act := range activity {
		if act.HasTXT {
			counts.WithTXT++
		}
		if act.LastUpdate <= 0 {
			counts.NeverUpdated++
			continue
		}
		updated = append(updated, act)
		age := now.Sub(time.Unix(act.LastUpdate, 0))
		if age <= day {
			counts.UpdatedLast24h++
		}
		if age <= 7*day {
			counts.UpdatedLast7d++
		}
		if age <= 30*day {
			counts.UpdatedLast30d++
		}
		if age <= 90*day {
			counts.UpdatedLast90d++
		} else {
			counts.Stale++
		}
	}
	sort.SliceStable(updated, func(i, j int) bool {
		if updated[i].LastUpdate != updated[j].LastUpdate {
			return updated[i].LastUpdate > updated[j].LastUpdate
		}
		return updated[i].Subdomain < updated[j].Subdomain
	})
	if recentLimit >= 0 && len(updated) > recentLimit {
		updated = updated[:recentLimit]
	}
	return counts, updated
}

func (a *API) adminDomain(info acmedns.DomainInfo) AdminDomain {
	resp := AdminDomain{
		Username:   info.Username.String(),
		Subdomain:  info.Subdomain,
		Fulldomain: a.fulldomain(info.Subdomain),
		Allowfrom:  info.AllowFrom.ValidEntries(),
		TXTRecords: make([]AdminTXTRecord, 0, len(info.TXT)),
		HasTXT:     info.HasTXT(),
		LastUpdate: unixTime(info.LastUpdate()),
	}
	for _, t := range info.TXT {
		resp.TXTRecords = append(resp.TXTRecords, AdminTXTRecord{Value: t.Value, LastUpdate: unixTime(t.LastUpdate)})
	}
	return resp
}

func (a *API) fulldomain(subdomain string) string {
	return subdomain + "." + a.Config.General.Domain
}

func unixTime(ts int64) *time.Time {
	if ts <= 0 {
		return nil
	}
	t := time.Unix(ts, 0).UTC()
	return &t
}

// parsePagination reads the limit and offset query parameters. Limits above
// AdminMaxLimit are clamped, anything non-numeric, negative or a zero limit is
// rejected.
func parsePagination(r *http.Request) (int, int, error) {
	limit := AdminDefaultLimit
	offset := 0
	q := r.URL.Query()
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return 0, 0, errors.New("invalid limit")
		}
		limit = n
	}
	if limit > AdminMaxLimit {
		limit = AdminMaxLimit
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return 0, 0, errors.New("invalid offset")
		}
		offset = n
	}
	return limit, offset, nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	body, err := json.Marshal(v)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Could not marshal JSON")
		writeJSONError(w, http.StatusInternalServerError, "json_error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(acmedns.JsonError(message))
}

// AdminSetTXTRequest is the request body for setting a TXT value via the admin API
type AdminSetTXTRequest struct {
	Value string `json:"txt"`
}

// maxAdminBodySize limits the size of request bodies accepted by the admin API
const maxAdminBodySize = 64 * 1024

// AdminDeleteDomain handles DELETE /admin/domains/:subdomain
func (a *API) AdminDeleteDomain(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	subdomain := p.ByName("subdomain")
	if !acmedns.ValidSubdomain(subdomain) {
		writeJSONError(w, http.StatusBadRequest, "bad_subdomain")
		return
	}
	err := a.DB.DeleteDomain(subdomain)
	if errors.Is(err, acmedns.ErrDomainNotFound) {
		writeJSONError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error(), "subdomain": subdomain}).Error("Error while deleting domain")
		writeJSONError(w, http.StatusInternalServerError, "db_error")
		return
	}
	log.WithFields(log.Fields{"subdomain": subdomain, "ips": a.requestIPs(r)}).Info("Domain deleted via admin API")
	w.WriteHeader(http.StatusNoContent)
}

// AdminSetTXT handles POST /admin/domains/:subdomain/txt. It performs the same
// rolling update of the two TXT values as the /update endpoint, but without
// per-domain credentials.
func (a *API) AdminSetTXT(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	subdomain := p.ByName("subdomain")
	if !acmedns.ValidSubdomain(subdomain) {
		writeJSONError(w, http.StatusBadRequest, "bad_subdomain")
		return
	}
	var body AdminSetTXTRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminBodySize))
	if err := dec.Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed_json_payload")
		return
	}
	if !acmedns.ValidTXT(body.Value) {
		log.WithFields(log.Fields{"error": "txt", "subdomain": subdomain, "txt": body.Value}).Debug("Bad admin update data")
		writeJSONError(w, http.StatusBadRequest, "bad_txt")
		return
	}
	if _, err := a.DB.GetDomain(subdomain); err != nil {
		if errors.Is(err, acmedns.ErrDomainNotFound) {
			writeJSONError(w, http.StatusNotFound, "not_found")
			return
		}
		log.WithFields(log.Fields{"error": err.Error(), "subdomain": subdomain}).Error("Error while fetching domain")
		writeJSONError(w, http.StatusInternalServerError, "db_error")
		return
	}
	if err := a.DB.Update(acmedns.ACMETxtPost{Subdomain: subdomain, Value: body.Value}); err != nil {
		log.WithFields(log.Fields{"error": err.Error(), "subdomain": subdomain}).Error("Error while trying to update record")
		writeJSONError(w, http.StatusInternalServerError, "db_error")
		return
	}
	log.WithFields(log.Fields{"subdomain": subdomain, "txt": body.Value, "ips": a.requestIPs(r)}).Info("TXT updated via admin API")
	info, err := a.DB.GetDomain(subdomain)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error(), "subdomain": subdomain}).Error("Error while fetching domain")
		writeJSONError(w, http.StatusInternalServerError, "db_error")
		return
	}
	writeJSON(w, http.StatusOK, a.adminDomain(info))
}
