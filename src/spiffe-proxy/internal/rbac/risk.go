// Package rbac — risk.go implements the in-memory agent risk store.
//
// The RiskStore holds per-agent risk levels (low/medium/high) that are
// updated by external threat signals (CrowdStrike mock, Microsoft Defender,
// etc.) via the management API and queried by the RBAC engine on every
// request for Layer 4b (data-plane CA) enforcement.
//
// In production, agent risk comes from Entra ID Protection and is evaluated
// at token issuance time (Layer 4a). The RiskStore simulates this for the PoC
// by checking risk at the data plane (Layer 4b).
package rbac

import (
	"log"
	"sync"
)

// Valid risk levels. These map to Entra ID Protection risk levels
// and the agentIdRiskLevels CA condition.
const (
	RiskLow    = "low"
	RiskMedium = "medium"
	RiskHigh   = "high"
)

// ValidRiskLevel returns true if the level is a recognized risk level.
func ValidRiskLevel(level string) bool {
	return level == RiskLow || level == RiskMedium || level == RiskHigh
}

// RiskStore holds per-agent risk levels in memory.
// Updated by external signals via the management API.
// Queried by the RBAC engine on every request.
//
// Thread-safe: uses sync.RWMutex because the mgmt API writes
// and the RBAC engine reads concurrently.
type RiskStore struct {
	mu    sync.RWMutex
	risks map[string]string // SPIFFE ID → risk level
}

// NewRiskStore creates an empty risk store.
// Unknown agents default to "low" risk.
func NewRiskStore() *RiskStore {
	return &RiskStore{
		risks: make(map[string]string),
	}
}

// GetRisk returns the risk level for the given SPIFFE ID.
// Returns "low" if the agent has no explicit risk entry.
func (rs *RiskStore) GetRisk(spiffeID string) string {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	if level, ok := rs.risks[spiffeID]; ok {
		return level
	}
	return RiskLow
}

// SetRisk updates the risk level for the given SPIFFE ID.
// Returns the previous risk level.
func (rs *RiskStore) SetRisk(spiffeID, level string) string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	prev := rs.risks[spiffeID]
	if prev == "" {
		prev = RiskLow
	}
	rs.risks[spiffeID] = level
	log.Printf("[RISK] Agent risk updated: %s → %s (was %s)", spiffeID, level, prev)
	return prev
}

// GetAll returns a snapshot of all risk levels.
func (rs *RiskStore) GetAll() map[string]string {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	snapshot := make(map[string]string, len(rs.risks))
	for k, v := range rs.risks {
		snapshot[k] = v
	}
	return snapshot
}

// Count returns the number of agents with explicit risk entries.
func (rs *RiskStore) Count() int {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return len(rs.risks)
}
