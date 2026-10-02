package protocols

import (
	"testing"
	"time"

	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/ca"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/rbac"
)

func TestEntraRisk(t *testing.T) {
	for _, name := range []string{"high_overrides_manual_low", "explicit_none", "unavailable", "missing", "invalid",
		"cached_rating", "zero_checks_every_call", "failed_refresh_no_fallback"} {
		t.Run(name, func(t *testing.T) {
			f := newIdentityFixture(t)
			f.policies = []any{graphPolicy("enabled", []string{"high"}, "block")}
			f.riskLevel = "low"
			p := basePolicy()
			p.Policies[0].EntraAgentID = "11111111-1111-4111-8111-111111111111"
			p.AdminGovernance.Enabled = true
			p.AdminGovernance.RiskEnforcement = "data_plane"
			seconds := int64(0)
			p.AdminGovernance.RiskCacheSeconds = &seconds
			local := rbac.NewRiskStore()
			local.SetRisk(caller, rbac.RiskLow)
			cache := ca.NewRiskCache(ca.NewGraphClient("fixture-tenant", "fixture", "fixture"))
			expected := rbac.ActionAllow
			switch name {
			case "high_overrides_manual_low":
				f.riskLevel, expected = "high", rbac.ActionDeny
			case "explicit_none":
				f.riskLevel = "none"
			case "unavailable":
				f.riskStatus, expected = 403, rbac.ActionDeny
			case "missing":
				f.riskStatus, expected = 404, rbac.ActionDeny
			case "invalid":
				f.riskLevel, expected = "unknownFutureValue", rbac.ActionDeny
			case "cached_rating":
				seconds = 90
			}
			e := engine(t, p, f.validator(), local, nil, f.cache(t, time.Hour), rbac.WithEntraRiskCache(cache))
			token := f.token(t, nil, false)
			got := e.Evaluate(caller, "GET", "/read", token)
			if got.Action != expected || (expected == rbac.ActionDeny && got.EnforcementLayer != rbac.LayerCA) {
				t.Fatalf("Entra runtime decision mismatch: %+v", got)
			}
			if name == "cached_rating" || name == "zero_checks_every_call" || name == "failed_refresh_no_fallback" {
				f.mu.Lock()
				f.riskLevel = "high"
				if name == "failed_refresh_no_fallback" {
					f.riskStatus = 503
				}
				f.mu.Unlock()
				got = e.Evaluate(caller, "GET", "/read", token)
				f.mu.Lock()
				calls := f.riskCalls
				f.mu.Unlock()
				if name == "cached_rating" {
					if got.Action != rbac.ActionAllow || calls != 1 {
						t.Fatal("fresh rating was not reused")
					}
				} else if got.Action != rbac.ActionDeny || got.EnforcementLayer != rbac.LayerCA || calls != 2 {
					t.Fatal("zero cache lifetime did not enforce a fresh lookup")
				}
			}
			logDecision(t, got)
		})
	}
}
