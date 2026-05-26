package ca

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// PolicyCache periodically fetches CA policies from Graph API and caches
// the effective blocked risk levels derived from agentIdRiskLevels conditions.
type PolicyCache struct {
	client   *GraphClient
	interval time.Duration

	mu            sync.RWMutex
	blockedLevels []string // union of all active policy blocked levels
	policies      []caCachedPolicy
	lastFetch     time.Time
	lastError     error
	fetchCount    int
	stopCh        chan struct{}
}

// caCachedPolicy holds a parsed representation of a CA policy.
// Stores the full policy conditions so it can be extended for tag evaluation later.
type caCachedPolicy struct {
	ID            string   `json:"id"`
	DisplayName   string   `json:"display_name"`
	State         string   `json:"state"`
	RiskLevels    []string `json:"risk_levels"`
	IsBlockPolicy bool     `json:"is_block_policy"`
	// TODO: Add tag filter fields when implementing CA-driven tag evaluation.
	// These would be parsed from conditions.clientApplications.servicePrincipalFilter
	// and conditions.applications.applicationFilter rule expressions.
}

// graphPoliciesResponse is the Graph API list response shape.
type graphPoliciesResponse struct {
	Value []graphPolicy `json:"value"`
}

type graphPolicy struct {
	ID          string             `json:"id"`
	DisplayName string             `json:"displayName"`
	State       string             `json:"state"`
	Conditions  graphConditions    `json:"conditions"`
	Grant       graphGrantControls `json:"grantControls"`
}

type graphConditions struct {
	AgentIDRiskLevels json.RawMessage `json:"agentIdRiskLevels"`
}

type graphGrantControls struct {
	BuiltInControls []string `json:"builtInControls"`
}

// NewPolicyCache creates a CA policy cache that syncs from Graph.
// If client is nil, the cache operates in pass-through mode (no Graph).
func NewPolicyCache(client *GraphClient, syncInterval time.Duration) *PolicyCache {
	if syncInterval <= 0 {
		syncInterval = 60 * time.Second
	}
	return &PolicyCache{
		client:   client,
		interval: syncInterval,
		stopCh:   make(chan struct{}),
	}
}

// Start begins the background sync goroutine. Call Stop() to terminate.
func (pc *PolicyCache) Start() {
	if pc.client == nil {
		log.Printf("[CA-Cache] Graph client not configured — CA policy cache disabled")
		return
	}

	// Initial fetch
	pc.refresh()

	go func() {
		ticker := time.NewTicker(pc.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				pc.refresh()
			case <-pc.stopCh:
				return
			}
		}
	}()
	log.Printf("[CA-Cache] Started — sync interval: %s", pc.interval)
}

// Stop terminates the background sync.
func (pc *PolicyCache) Stop() {
	close(pc.stopCh)
}

// GetBlockedRiskLevels returns the set of risk levels that should be blocked
// based on enabled CA policies. Returns nil if Graph is not configured or
// no policies have agentIdRiskLevels conditions.
func (pc *PolicyCache) GetBlockedRiskLevels() []string {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.blockedLevels
}

// SetBlockedRiskLevelsForTest sets blocked risk levels directly for unit testing.
// Production code should never call this — use Start() to sync from Graph.
func (pc *PolicyCache) SetBlockedRiskLevelsForTest(levels []string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.blockedLevels = levels
}

// GetCachedPolicies returns a snapshot of all cached CA policies for debugging.
func (pc *PolicyCache) GetCachedPolicies() []caCachedPolicy {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	cp := make([]caCachedPolicy, len(pc.policies))
	copy(cp, pc.policies)
	return cp
}

// Status returns cache health info for the management API.
func (pc *PolicyCache) Status() map[string]interface{} {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	status := map[string]interface{}{
		"enabled":             pc.client != nil,
		"blocked_risk_levels": pc.blockedLevels,
		"policy_count":        len(pc.policies),
		"fetch_count":         pc.fetchCount,
		"sync_interval":       pc.interval.String(),
	}
	if !pc.lastFetch.IsZero() {
		status["last_fetch"] = pc.lastFetch.Format(time.RFC3339)
		status["age_seconds"] = int(time.Since(pc.lastFetch).Seconds())
	}
	if pc.lastError != nil {
		status["last_error"] = pc.lastError.Error()
	}
	return status
}

// refresh fetches CA policies from Graph and updates the cache.
func (pc *PolicyCache) refresh() {
	// Fetch all CA policies (no $filter — Graph beta rejects OR expressions).
	// We filter client-side to enabled + report-only policies.
	url := fmt.Sprintf("%s/identity/conditionalAccess/policies", graphBeta)

	body, err := pc.client.Get(url)
	if err != nil {
		log.Printf("[CA-Cache] Fetch failed: %v", err)
		pc.mu.Lock()
		pc.lastError = err
		pc.mu.Unlock()
		return
	}

	var resp graphPoliciesResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		log.Printf("[CA-Cache] Parse failed: %v", err)
		pc.mu.Lock()
		pc.lastError = fmt.Errorf("parse: %w", err)
		pc.mu.Unlock()
		return
	}

	var policies []caCachedPolicy
	blockedSet := make(map[string]bool)

	for _, p := range resp.Value {
		// Skip disabled policies (only process enabled + report-only)
		if p.State != "enabled" && p.State != "enabledForReportingButNotEnforced" {
			continue
		}

		riskLevels := parseRiskLevels(p.Conditions.AgentIDRiskLevels)
		if len(riskLevels) == 0 {
			continue // Not a risk-based CA policy
		}

		isBlock := false
		for _, ctrl := range p.Grant.BuiltInControls {
			if ctrl == "block" {
				isBlock = true
				break
			}
		}

		cached := caCachedPolicy{
			ID:            p.ID,
			DisplayName:   p.DisplayName,
			State:         p.State,
			RiskLevels:    riskLevels,
			IsBlockPolicy: isBlock,
		}
		policies = append(policies, cached)

		// Only enforce blocking for enabled policies (not report-only)
		if isBlock && p.State == "enabled" {
			for _, level := range riskLevels {
				blockedSet[level] = true
			}
		} else if isBlock && p.State == "enabledForReportingButNotEnforced" {
			for _, level := range riskLevels {
				log.Printf("[CA-Cache] Report-only: policy %q would block risk level %q", p.DisplayName, level)
			}
		}
	}

	blocked := make([]string, 0, len(blockedSet))
	for level := range blockedSet {
		blocked = append(blocked, level)
	}

	pc.mu.Lock()
	pc.blockedLevels = blocked
	pc.policies = policies
	pc.lastFetch = time.Now()
	pc.lastError = nil
	pc.fetchCount++
	pc.mu.Unlock()

	log.Printf("[CA-Cache] Refreshed: %d risk policies, blocked levels: %v", len(policies), blocked)
}

// parseRiskLevels handles the agentIdRiskLevels field which can be
// a string (single value) or an array of strings.
func parseRiskLevels(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}

	// Try as string first (single value like "high")
	var single string
	if err := json.Unmarshal(raw, &single); err == nil && single != "" {
		return []string{single}
	}

	// Try as array
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}

	return nil
}
