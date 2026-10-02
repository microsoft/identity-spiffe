package rbac

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/ca"
)

type entraTransport func(*http.Request) (*http.Response, error)

func (f entraTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestEntraRuntimeRiskCannotUseManualSafeFallback(t *testing.T) {
	const agentID = "11111111-1111-4111-8111-111111111111"
	const caller = "spiffe://entra.test/ests/bp/blueprint/aid/" + agentID
	for _, tc := range []struct {
		name, entra, local, want string
		status                   int
	}{
		{"entra-high-manual-low", "high", RiskLow, "high_risk_agent_blocked", 200},
		{"entra-low-manual-high", "low", RiskHigh, "high_risk_agent_blocked", 200},
		{"entra-explicit-none", "none", RiskUnknown, "matched_rule", 200},
		{"unlicensed-manual-low", "", RiskLow, "agent_risk_unavailable", 403},
		{"missing-manual-low", "", RiskLow, "agent_risk_unavailable", 404},
		{"invalid-manual-low", "unknownFutureValue", RiskLow, "agent_risk_unavailable", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := http.DefaultTransport
			calls := 0
			http.DefaultTransport = entraTransport(func(r *http.Request) (*http.Response, error) {
				body, status := `{"access_token":"fixture","expires_in":3600}`, 200
				if r.URL.Host == "graph.microsoft.com" {
					calls++
					if r.URL.Path != "/beta/identityProtection/riskyAgents/"+agentID {
						t.Fatalf("risk was queried for wrong caller")
					}
					body, status = fmt.Sprintf(`{"id":%q,"riskLevel":%q}`, agentID, tc.entra), tc.status
				} else if r.URL.Host != "login.microsoftonline.com" {
					t.Fatal("unexpected outbound destination")
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
			})
			t.Cleanup(func() { http.DefaultTransport = old })
			store := NewPolicyStore()
			text := fmt.Sprintf(`version: "test"
trust_domain: entra.test
default_action: deny
admin_governance:
  enabled: true
  risk_enforcement: data_plane
  risk_cache_seconds: 0
policies:
  - spiffe_id: %s
    entra_agent_id: %s
    rules:
      - path: /read
        methods: [GET]
        action: allow
`, caller, agentID)
			if err := store.LoadFromBytes([]byte(text)); err != nil {
				t.Fatal(err)
			}
			policies := ca.NewPolicyCache(nil, 0)
			policies.SetBlockedRiskLevelsForTest([]string{"high"})
			local := NewRiskStore()
			local.SetRisk(caller, tc.local)
			cache := ca.NewRiskCache(ca.NewGraphClient("fixture", "fixture", "fixture"))
			engine := NewEngine(store, nil, local, nil, WithCAPolicyCache(policies), WithEntraRiskCache(cache))
			for i := 0; i < 2; i++ {
				got := engine.Evaluate(caller, "GET", "/read", "")
				if got.Reason != tc.want || (got.Action == ActionAllow) != (tc.want == "matched_rule") {
					t.Fatalf("runtime risk decision: %+v", got)
				}
			}
			if calls != 2 {
				t.Fatalf("zero lifetime must fetch on every call: %d", calls)
			}
			p := *store.Get()
			cp := p.Policies[0]
			cp.EntraAgentID = "22222222-2222-4222-8222-222222222222"
			if _, err := EntraCallerRisk(&p, &cp, caller, cache); err == nil {
				t.Fatal("mismatched SPIFFE/Entra identity accepted")
			}
		})
	}
}

func TestRiskCachePolicyDefaultAndValidation(t *testing.T) {
	if got := (AdminGovernance{}).RiskCacheLifetime().Seconds(); got != 90 {
		t.Fatalf("default cache lifetime = %v", got)
	}
	p := &Policy{Version: "test"}
	for _, seconds := range []int64{-1, ca.MaxRiskCacheSeconds + 1} {
		p.AdminGovernance.RiskCacheSeconds = &seconds
		if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "risk_cache_seconds") {
			t.Fatalf("invalid cache lifetime accepted: %v", err)
		}
	}
}
