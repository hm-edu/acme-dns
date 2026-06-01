package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hm-edu/acme-dns/pkg/acmedns"
	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
)

// API holds the dependencies for the HTTP handlers
type API struct {
	Config *acmedns.DNSConfig
	DB     acmedns.Database
}

// RegResponse is the JSON response body for registration
type RegResponse struct {
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	Fulldomain string   `json:"fulldomain"`
	Subdomain  string   `json:"subdomain"`
	Allowfrom  []string `json:"allowfrom"`
}

// RegisterPost handles POST /register
func (a *API) RegisterPost(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var regStatus int
	var reg []byte
	var err error
	aTXT := acmedns.ACMETxt{}
	bdata, _ := io.ReadAll(r.Body)
	if len(bdata) > 0 {
		err = json.Unmarshal(bdata, &aTXT)
		if err != nil {
			regStatus = http.StatusBadRequest
			reg = acmedns.JsonError("malformed_json_payload")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(regStatus)
			_, _ = w.Write(reg)
			return
		}
	}

	err = aTXT.AllowFrom.IsValid()
	if err != nil {
		regStatus = http.StatusBadRequest
		reg = acmedns.JsonError("invalid_allowfrom_cidr")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(regStatus)
		_, _ = w.Write(reg)
		return
	}

	nu, err := a.DB.Register(aTXT.AllowFrom)
	if err != nil {
		errstr := fmt.Sprintf("%v", err)
		reg = acmedns.JsonError(errstr)
		regStatus = http.StatusInternalServerError
		log.WithFields(log.Fields{"error": err.Error()}).Debug("Error in registration")
	} else {
		log.WithFields(log.Fields{"user": nu.Username.String()}).Debug("Created new user")
		regStruct := RegResponse{
			nu.Username.String(),
			nu.Password,
			nu.Subdomain + "." + a.Config.General.Domain,
			nu.Subdomain,
			nu.AllowFrom.ValidEntries(),
		}
		regStatus = http.StatusCreated
		reg, err = json.Marshal(regStruct)
		if err != nil {
			regStatus = http.StatusInternalServerError
			reg = acmedns.JsonError("json_error")
			log.WithFields(log.Fields{"error": "json"}).Debug("Could not marshal JSON")
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(regStatus)
	_, _ = w.Write(reg)
}

// UpdatePost handles POST /update
func (a *API) UpdatePost(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var updStatus int
	var upd []byte
	ctx, ok := r.Context().Value(ACMETxtKey).(acmedns.ACMETxt)
	if !ok {
		log.WithFields(log.Fields{"error": "context"}).Error("Context error")
	}
	if !acmedns.ValidSubdomain(ctx.Subdomain) {
		log.WithFields(log.Fields{"error": "subdomain", "subdomain": ctx.Subdomain, "txt": ctx.Value}).Debug("Bad update data")
		updStatus = http.StatusBadRequest
		upd = acmedns.JsonError("bad_subdomain")
	} else if !acmedns.ValidTXT(ctx.Value) {
		log.WithFields(log.Fields{"error": "txt", "subdomain": ctx.Subdomain, "txt": ctx.Value}).Debug("Bad update data")
		updStatus = http.StatusBadRequest
		upd = acmedns.JsonError("bad_txt")
	} else if acmedns.ValidSubdomain(ctx.Subdomain) && acmedns.ValidTXT(ctx.Value) {
		err := a.DB.Update(ctx.ACMETxtPost)
		if err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Debug("Error while trying to update record")
			updStatus = http.StatusInternalServerError
			upd = acmedns.JsonError("db_error")
		} else {
			log.WithFields(log.Fields{"subdomain": ctx.Subdomain, "txt": ctx.Value}).Debug("TXT updated")
			updStatus = http.StatusOK
			upd = []byte("{\"txt\": \"" + ctx.Value + "\"}")
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(updStatus)
	_, _ = w.Write(upd)
}

// HealthCheck handles GET /health
func HealthCheck(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.WriteHeader(http.StatusOK)
}
