package protocols

import (
	"testing"
	"time"

	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/rbac"
)

func TestCA(t *testing.T) {
	names := []string{
		"enabled_low", "enabled_high", "enabled_medium", "disabled_policy", "report_only", "nonblock_policy",
		"string_risk", "union_risk", "tag_match", "tag_mismatch", "tag_missing", "tag_graph_override",
		"tag_exemption", "disabled_agent", "policy_outage", "missing_risk", "graph_tag_absent", "warm_policy_outage",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			f := newIdentityFixture(t)
			p := basePolicy()
			p.AdminGovernance = rbac.AdminGovernance{Enabled: true, TargetAgentTag: "Finance", RiskEnforcement: "data_plane"}
			state, controls := "enabled", []string{"block"}
			var levels any = []string{"high"}
			risk := rbac.NewRiskStore()
			tags := rbac.NewTagStore()
			tags.SetTag(caller, "Finance")
			risk.SetRisk(caller, rbac.RiskLow)
			action, layer, reason, status := rbac.ActionAllow, rbac.LayerOAuth, "matched_rule", 0
			switch name {
			case "enabled_high", "enabled_medium", "string_risk", "union_risk", "warm_policy_outage":
				action, layer, reason, status = rbac.ActionDeny, rbac.LayerCA, "high_risk_agent_blocked", 403
				risk.SetRisk(caller, rbac.RiskHigh)
			case "tag_mismatch", "tag_missing", "tag_graph_override":
				action, layer, reason, status = rbac.ActionDeny, rbac.LayerCA, "agent_tag_mismatch", 403
			case "disabled_agent":
				action, layer, reason, status = rbac.ActionDeny, rbac.LayerCA, "agent_disabled", 403
			}
			switch name {
			case "enabled_medium":
				levels = []string{"medium"}
				risk.SetRisk(caller, rbac.RiskMedium)
			case "disabled_policy":
				state = "disabled"
				risk.SetRisk(caller, rbac.RiskHigh)
			case "report_only":
				state = "enabledForReportingButNotEnforced"
				risk.SetRisk(caller, rbac.RiskHigh)
			case "nonblock_policy":
				controls = []string{"mfa"}
				risk.SetRisk(caller, rbac.RiskHigh)
			case "string_risk":
				levels = "high"
			case "tag_match":
				tags.SetTag(caller, "finance")
			case "tag_mismatch", "tag_graph_override":
				tags.SetTag(caller, "Engineering")
			case "tag_missing":
				tags.RemoveTag(caller)
				p.Policies[0].CA.AgentTag = ""
			case "tag_exemption":
				tags.SetTag(caller, "Engineering")
				p.Policies[0].CA.SkipTargetTagCheck = true
			case "disabled_agent":
				p.Policies[0].CA.SkipTargetTagCheck = true
				p.Policies[0].CA.AgentState = "disabled"
			case "policy_outage":
				f.outage = true
				risk.SetRisk(caller, rbac.RiskHigh)
			case "missing_risk":
				risk = rbac.NewRiskStore()
			case "graph_tag_absent":
				tags.RemoveTag(caller)
			}
			f.policies = []any{graphPolicy(state, levels, controls...)}
			if name == "union_risk" {
				f.policies = []any{
					graphPolicy("enabled", []string{"medium"}, "block"),
					graphPolicy("enabled", []string{"high"}, "block"),
				}
			}
			cache := f.cache(t, time.Hour)
			if name == "policy_outage" {
				if _, ok := cache.Status()["last_error"]; !ok {
					t.Fatal("fixture outage did not reach real Graph cache")
				}
			} else if cache.Status()["fetch_count"].(int) < 1 {
				t.Fatal("real Graph policy cache did not parse fixture")
			}
			if name == "warm_policy_outage" {
				f.mu.Lock()
				f.outage = true
				f.mu.Unlock()
				// Start performs a synchronous refresh. Calling it again drives
				// the same real refresh against the warm cache, without timer
				// races. One Stop closes the shared channel for both idle loops.
				cache.Start()
				if _, ok := cache.Status()["last_error"]; !ok {
					t.Fatal("warm cache never observed outage")
				}
			}
			e := engine(t, p, f.validator(), risk, tags, cache)
			got := e.Evaluate(caller, "GET", "/read", f.token(t, nil, false))
			if name == "policy_outage" || name == "missing_risk" || name == "graph_tag_absent" {
				logDecision(t, got)
				// Assert the repository's fail-closed security contract, not its
				// current permissive fallback. Defects must stay visible as FAIL.
				if got.Action != rbac.ActionDeny || got.EnforcementLayer != rbac.LayerCA {
					t.Fatalf("missing governance evidence allowed access: action=%s layer=%s reason=%s",
						got.Action, got.EnforcementLayer, got.Reason)
				}
				return
			}
			assertDecision(t, got, action, layer, reason, status)
			if name == "union_risk" {
				risk.SetRisk(caller, rbac.RiskMedium)
				assertDecision(t, e.Evaluate(caller, "GET", "/read", f.token(t, nil, false)),
					rbac.ActionDeny, rbac.LayerCA, "high_risk_agent_blocked", 403)
			}
		})
	}
}
