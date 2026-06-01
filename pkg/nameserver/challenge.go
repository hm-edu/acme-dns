package nameserver

import (
	"context"
	"strings"

	"github.com/libdns/libdns"
	log "github.com/sirupsen/logrus"
)

// ChallengeProvider implements the libdns Provider interface for ACME DNS-01 challenges
type ChallengeProvider struct {
	servers []*DNSServer
}

// NewChallengeProvider creates a new ChallengeProvider
func NewChallengeProvider(servers []*DNSServer) ChallengeProvider {
	return ChallengeProvider{servers: servers}
}

// AppendRecords sets the ACME challenge token on all DNS servers
func (c *ChallengeProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	var token string
	for _, item := range recs {
		log.WithFields(log.Fields{"name": item.RR().Name, "value": item.RR().Data, "type": item.RR().Type}).Info("Attempting to set dns record")
		if strings.Contains(item.RR().Name, "acme-challenge") {
			token = item.RR().Data
			break
		}
	}

	for _, s := range c.servers {
		s.PersonalKeyAuth = token
	}
	return recs, nil
}

// DeleteRecords clears the ACME challenge token from all DNS servers
func (c *ChallengeProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	for _, item := range recs {
		log.WithFields(log.Fields{"name": item.RR().Name, "value": item.RR().Data, "type": item.RR().Type}).Info("Attempting to unset dns record")
	}
	for _, s := range c.servers {
		s.PersonalKeyAuth = ""
	}
	return recs, nil
}
