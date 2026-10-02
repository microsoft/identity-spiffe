package ca

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
)

const DefaultRiskCacheSeconds = 90
const MaxRiskCacheSeconds = int64((1<<63 - 1) / time.Second)

type riskEvidence struct {
	mu        sync.Mutex
	level     string
	fetchedAt time.Time
}

// RiskCache holds only explicit Entra ratings, keyed by service principal object ID.
// Failed reads invalidate evidence; neither a 404 nor a manual rating supplies safety.
type RiskCache struct {
	client  *GraphClient
	mu      sync.Mutex
	entries map[string]*riskEvidence
	now     func() time.Time
}

func NewRiskCache(client *GraphClient) *RiskCache {
	return &RiskCache{client: client, entries: make(map[string]*riskEvidence), now: time.Now}
}

func (c *RiskCache) GetRisk(agentID string, maxAge time.Duration) (string, error) {
	if c == nil || c.client == nil {
		return "", fmt.Errorf("Entra risk credentials unavailable")
	}
	id, err := uuid.Parse(agentID)
	if err != nil || id == uuid.Nil || maxAge < 0 {
		return "", fmt.Errorf("invalid Entra risk identity or cache lifetime")
	}
	agentID = id.String()
	c.mu.Lock()
	entry := c.entries[agentID]
	if entry == nil {
		entry = &riskEvidence{}
		c.entries[agentID] = entry
	}
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()
	started := c.now()
	if maxAge > 0 && !entry.fetchedAt.IsZero() && started.Sub(entry.fetchedAt) >= 0 &&
		started.Sub(entry.fetchedAt) < maxAge {
		return entry.level, nil
	}
	body, err := c.client.Get(graphBeta + "/identityProtection/riskyAgents/" + agentID)
	var result struct {
		ID    string `json:"id"`
		Level string `json:"riskLevel"`
	}
	if err == nil {
		err = json.Unmarshal(body, &result)
	}
	if err == nil {
		responseID, parseErr := uuid.Parse(result.ID)
		if parseErr != nil || responseID != id {
			err = fmt.Errorf("Entra risk response identity mismatch")
		} else if result.Level != "none" && result.Level != "low" && result.Level != "medium" && result.Level != "high" {
			err = fmt.Errorf("Entra risk response has no recognized rating")
		} else if maxAge > 0 && c.now().Sub(started) >= maxAge {
			err = fmt.Errorf("Entra risk lookup exceeded cache lifetime")
		}
	}
	if err != nil {
		entry.level, entry.fetchedAt = "", time.Time{}
		log.Printf("[Entra-Risk] Lookup unavailable for %s: %v", agentID, err)
		return "", err
	}
	entry.level, entry.fetchedAt = result.Level, started
	return entry.level, nil
}
