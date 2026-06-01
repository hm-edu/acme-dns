package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/hm-edu/acme-dns/pkg/acmedns"
	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
)

type contextKey int

// ACMETxtKey is the context key for ACMETxt values
const ACMETxtKey contextKey = 0

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

func (a *API) updateAllowedFromIP(r *http.Request, user acmedns.ACMETxt) bool {
	if a.Config.API.UseHeader {
		ips := acmedns.GetIPListFromHeader(r.Header.Get(a.Config.API.HeaderName))
		return user.AllowedFromList(ips)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error(), "remoteaddr": r.RemoteAddr}).Error("Error while parsing remote address")
		host = ""
	}
	return user.AllowedFrom(host)
}
