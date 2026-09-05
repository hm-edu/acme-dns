package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/hm-edu/acme-dns/pkg/acmedns"
	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
)

type contextKey int

// ACMETxtKey is the context key for ACMETxt values
const ACMETxtKey contextKey = 0

// AdminKeyHeader is the header carrying the admin API key. Alternatively the
// key can be sent as a bearer token in the Authorization header.
const AdminKeyHeader = "X-Admin-Key"

// Auth is the authentication middleware for update requests
func (a *API) Auth(update httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		postData := acmedns.ACMETxt{}
		userOK := false
		user, err := a.getUserFromRequest(r)
		if err == nil {
			if a.updateAllowedFromIP(r, user) {
				dec := json.NewDecoder(r.Body)
				err = dec.Decode(&postData)
				if err != nil {
					log.WithFields(log.Fields{"error": "json_error", "string": err.Error()}).Error("Decode error")
				}
				if user.Subdomain == postData.Subdomain {
					userOK = true
				} else {
					log.WithFields(log.Fields{"error": "subdomain_mismatch", "name": postData.Subdomain, "expected": user.Subdomain}).Error("Subdomain mismatch")
				}
			} else {
				log.WithFields(log.Fields{"error": "ip_unauthorized"}).Error("Update not allowed from IP")
			}
		} else {
			log.WithFields(log.Fields{"error": err.Error()}).Error("Error while trying to get user")
		}
		if userOK {
			postData.Username = user.Username
			postData.Password = user.Password
			ctx := context.WithValue(r.Context(), ACMETxtKey, postData)
			update(w, r.WithContext(ctx), p)
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write(acmedns.JsonError("forbidden"))
		}
	}
}

// AdminAuth is the authentication middleware for the admin API. The optional
// source IP allowlist is checked first, then the API key.
func (a *API) AdminAuth(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		ips := a.requestIPs(r)
		if !a.Config.Admin.AllowFrom.AllowsAny(ips) {
			log.WithFields(log.Fields{"error": "ip_unauthorized", "ips": ips, "path": r.URL.Path}).Warn("Admin API access not allowed from IP")
			writeJSONError(w, http.StatusForbidden, "forbidden")
			return
		}
		if !a.validAdminKey(adminKeyFromRequest(r)) {
			log.WithFields(log.Fields{"error": "invalid_api_key", "ips": ips, "path": r.URL.Path}).Warn("Admin API access with invalid API key")
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r, p)
	}
}

func adminKeyFromRequest(r *http.Request) string {
	if key := r.Header.Get(AdminKeyHeader); key != "" {
		return key
	}
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}

func (a *API) validAdminKey(key string) bool {
	expected := a.Config.Admin.APIKey
	if key == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(key), []byte(expected)) == 1
}

func (a *API) getUserFromRequest(r *http.Request) (acmedns.ACMETxt, error) {
	uname := r.Header.Get("X-Api-User")
	passwd := r.Header.Get("X-Api-Key")
	username, err := acmedns.GetValidUsername(uname)
	if err != nil {
		return acmedns.ACMETxt{}, fmt.Errorf("invalid username: %s: %s", uname, err.Error())
	}
	if acmedns.ValidKey(passwd) {
		dbuser, err := a.DB.GetByUsername(username)
		if err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Error("Error while trying to get user")
			// Protect against timed side channel
			acmedns.CorrectPassword(passwd, "$2a$10$8JEFVNYYhLoBysjAxe2yBuXrkDojBQBkVpXEQgyQyjn43SvJ4vL36")
			return acmedns.ACMETxt{}, fmt.Errorf("invalid username: %s", uname)
		}
		if acmedns.CorrectPassword(passwd, dbuser.Password) {
			return dbuser, nil
		}
		return acmedns.ACMETxt{}, fmt.Errorf("invalid password for user %s", uname)
	}
	return acmedns.ACMETxt{}, fmt.Errorf("invalid key for user %s", uname)
}

// requestIPs returns the client IP addresses of a request, either taken from
// the configured header or from the remote address of the connection.
func (a *API) requestIPs(r *http.Request) []string {
	if a.Config.API.UseHeader {
		return acmedns.GetIPListFromHeader(r.Header.Get(a.Config.API.HeaderName))
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error(), "remoteaddr": r.RemoteAddr}).Error("Error while parsing remote address")
		return []string{}
	}
	return []string{host}
}

func (a *API) updateAllowedFromIP(r *http.Request, user acmedns.ACMETxt) bool {
	return user.AllowedFromList(a.requestIPs(r))
}
