package main

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"strings"
	"time"
)

// toFQDN ensures a DNS name ends with a trailing dot for consistent storage and lookup.
func toFQDN(name string) string {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// stripOuterQuotes removes a single layer of surrounding double-quotes from TXT values
// so the DB always stores the raw string content regardless of how the caller supplied it.
func stripOuterQuotes(value string) string {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return value[1 : len(value)-1]
	}
	return value
}

// probeRR validates that rtype+value form a parseable DNS RR using a placeholder name and TTL.
func probeRR(rtype, value string) bool {
	if rtype == "TXT" {
		value = `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
	}
	_, err := dns.NewRR(fmt.Sprintf("probe.invalid. 300 IN %s %s", rtype, value))
	return err == nil
}
// RegResponse is a struct for registration response JSON
type RegResponse struct {
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	Fulldomain string   `json:"fulldomain"`
	Subdomain  string   `json:"subdomain"`
	Allowfrom  []string `json:"allowfrom"`
}

func webRegisterPost(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var regStatus int
	var reg []byte
	var err error
	aTXT := ACMETxt{}
	bdata, _ := io.ReadAll(r.Body)
	if len(bdata) > 0 {
		err = json.Unmarshal(bdata, &aTXT)
		if err != nil {
			regStatus = http.StatusBadRequest
			reg = jsonError("malformed_json_payload")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(regStatus)
			_, _ = w.Write(reg)
			return
		}
	}

	// Fail with malformed CIDR mask in allowfrom
	err = aTXT.AllowFrom.isValid()
	if err != nil {
		regStatus = http.StatusBadRequest
		reg = jsonError("invalid_allowfrom_cidr")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(regStatus)
		_, _ = w.Write(reg)
		return
	}

	// Create new user
	nu, err := DB.Register(aTXT.AllowFrom)
	if err != nil {
		errstr := fmt.Sprintf("%v", err)
		reg = jsonError(errstr)
		regStatus = http.StatusInternalServerError
		log.WithFields(log.Fields{"error": err.Error()}).Debug("Error in registration")
	} else {
		log.WithFields(log.Fields{"user": nu.Username.String()}).Debug("Created new user")
		regStruct := RegResponse{nu.Username.String(), nu.Password, nu.Subdomain + "." + Config.General.Domain, nu.Subdomain, nu.AllowFrom.ValidEntries()}
		regStatus = http.StatusCreated
		reg, err = json.Marshal(regStruct)
		if err != nil {
			regStatus = http.StatusInternalServerError
			reg = jsonError("json_error")
			log.WithFields(log.Fields{"error": "json"}).Debug("Could not marshal JSON")
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(regStatus)
	_, _ = w.Write(reg)
}

func webUpdatePost(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var updStatus int
	var upd []byte
	// Get user
	a, ok := r.Context().Value(ACMETxtKey).(ACMETxt)
	if !ok {
		log.WithFields(log.Fields{"error": "context"}).Error("Context error")
	}
	// NOTE: An invalid subdomain should not happen - the auth handler should
	// reject POSTs with an invalid subdomain before this handler. Reject any
	// invalid subdomains anyway as a matter of caution.
	if !validSubdomain(a.Subdomain) {
		log.WithFields(log.Fields{"error": "subdomain", "subdomain": a.Subdomain, "txt": a.Value}).Debug("Bad update data")
		updStatus = http.StatusBadRequest
		upd = jsonError("bad_subdomain")
	} else if !validTXT(a.Value) {
		log.WithFields(log.Fields{"error": "txt", "subdomain": a.Subdomain, "txt": a.Value}).Debug("Bad update data")
		updStatus = http.StatusBadRequest
		upd = jsonError("bad_txt")
	} else if validSubdomain(a.Subdomain) && validTXT(a.Value) {
		err := DB.Update(a.ACMETxtPost)
		if err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Debug("Error while trying to update record")
			updStatus = http.StatusInternalServerError
			upd = jsonError("db_error")
		} else {
			log.WithFields(log.Fields{"subdomain": a.Subdomain, "txt": a.Value}).Debug("TXT updated")
			updStatus = http.StatusOK
			upd = []byte("{\"txt\": \"" + a.Value + "\"}")
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(updStatus)
	_, _ = w.Write(upd)
}

// Endpoint used to check the readiness and/or liveness (health) of the server.
func healthCheck(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.WriteHeader(http.StatusOK)
}

// adminRecordRequest is the request body for creating/updating a DNS record
type adminRecordRequest struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

func adminBearerMiddleware(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		token := Config.API.Admin.Token
		auth := r.Header.Get("Authorization")
		provided := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(provided)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write(jsonError("unauthorized"))
			return
		}
		next(w, r, ps)
	}
}

func adminListRecords(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	filterType := strings.ToUpper(r.URL.Query().Get("type"))
	filterName := r.URL.Query().Get("name")
	if filterName != "" {
		filterName = toFQDN(filterName)
	}
	records, err := DB.ListRecords(filterType, filterName)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Error in admin handler")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(jsonError("db_error"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(records)
}

func adminCreateRecord(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var req adminRecordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(jsonError("malformed_json_payload"))
		return
	}
	if req.Name == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(jsonError("invalid_name"))
		return
	}
	if !validRecordType(req.Type) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(jsonError("invalid_record_type"))
		return
	}
	if !validRecordValue(req.Type, req.Value) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(jsonError("invalid_record_value"))
		return
	}
	if !probeRR(req.Type, req.Value) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(jsonError("invalid_record_value"))
		return
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = 300
	}
	if !validTTL(ttl) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(jsonError("invalid_ttl"))
		return
	}
	rec := DNSRecord{
		ID:      uuid.New().String(),
		Name:    toFQDN(req.Name),
		Type:    req.Type,
		Value:   stripOuterQuotes(req.Value),
		TTL:     ttl,
		Created: time.Now().Unix(),
	}
	if err := DB.CreateRecord(rec); err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Error in admin handler")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(jsonError("db_error"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(rec)
}

func adminUpdateRecord(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")
	var req adminRecordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(jsonError("malformed_json_payload"))
		return
	}
	if req.Name == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(jsonError("invalid_name"))
		return
	}
	if !validRecordType(req.Type) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(jsonError("invalid_record_type"))
		return
	}
	if !validRecordValue(req.Type, req.Value) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(jsonError("invalid_record_value"))
		return
	}
	if !probeRR(req.Type, req.Value) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(jsonError("invalid_record_value"))
		return
	}
	if req.TTL != 0 && !validTTL(req.TTL) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(jsonError("invalid_ttl"))
		return
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = 300
	}
	rec := DNSRecord{ID: id, Name: toFQDN(req.Name), Type: req.Type, Value: stripOuterQuotes(req.Value), TTL: ttl}
	if err := DB.UpdateRecord(rec); err != nil {
		w.Header().Set("Content-Type", "application/json")
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write(jsonError("record_not_found"))
		} else {
			log.WithFields(log.Fields{"error": err.Error()}).Error("Error in admin handler")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write(jsonError("db_error"))
		}
		return
	}
	// Fetch the full updated record to include the original Created timestamp
	updated, err := DB.GetRecord(id)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Error in admin handler")
		w.Header().Set("Content-Type", "application/json")
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write(jsonError("record_not_found"))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write(jsonError("db_error"))
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(updated)
}

func adminDeleteRecord(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")
	if err := DB.DeleteRecord(id); err != nil {
		w.Header().Set("Content-Type", "application/json")
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write(jsonError("record_not_found"))
		} else {
			log.WithFields(log.Fields{"error": err.Error()}).Error("Error in admin handler")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write(jsonError("db_error"))
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
