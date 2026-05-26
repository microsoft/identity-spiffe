package rbac

import (
	"fmt"
	"strings"
	"testing"

	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/ca"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/oauth"
)

const testPolicyYAML = `
version: "1.0"
trust_domain: "aim.microsoft.com"
default_action: deny

policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    description: "Read-only access to budget data"
    rules:
      - path: "/budget/read"
        methods: ["GET", "POST"]
        action: allow
      - path: "/budget/submit"
        methods: ["*"]
        action: deny

  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/employee-menus"
    description: "No network/STS access - blocked at mTLS layer"
    rules:
      - path: "/*"
        methods: ["*"]
        action: deny

  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-approval"
    description: "Can read and submit budgets"
    rules:
      - path: "/budget/read"
        methods: ["GET", "POST"]
        action: allow
      - path: "/budget/submit"
        methods: ["POST"]
        action: allow
`

func setupTestEngine(t *testing.T) *Engine {
	t.Helper()
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testPolicyYAML)); err != nil {
		t.Fatalf("Failed to load test policy: %v", err)
	}
	return NewEngine(store, nil, nil, nil)
}

// ─── Budget Backend Scenario Tests ───

func TestScenario1_BudgetReport_GET_BudgetRead_Allowed(t *testing.T) {
	e := setupTestEngine(t)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/budget/read", "")
	if d.Action != ActionAllow {
		t.Errorf("Scenario 1: expected ALLOW, got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestScenario2_BudgetReport_POST_BudgetSubmit_Denied(t *testing.T) {
	e := setupTestEngine(t)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "POST", "/budget/submit", "")
	if d.Action != ActionDeny {
		t.Errorf("Scenario 2: expected DENY, got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestScenario3_EmployeeMenus_AllPaths_Denied(t *testing.T) {
	e := setupTestEngine(t)
	paths := []string{"/budget/read", "/budget/submit", "/anything"}
	for _, p := range paths {
		d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/employee-menus", "GET", p, "")
		if d.Action != ActionDeny {
			t.Errorf("EmployeeMenus on %s: expected DENY, got %s", p, d.Action)
		}
	}
}

func TestScenario4_BudgetApproval_POST_BudgetSubmit_Allowed(t *testing.T) {
	e := setupTestEngine(t)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-approval", "POST", "/budget/submit", "")
	if d.Action != ActionAllow {
		t.Errorf("Scenario 4: expected ALLOW, got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestScenario5_BudgetApproval_GET_BudgetRead_Allowed(t *testing.T) {
	e := setupTestEngine(t)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-approval", "GET", "/budget/read", "")
	if d.Action != ActionAllow {
		t.Errorf("Scenario 5: expected ALLOW, got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestUnknownCaller_DefaultDeny(t *testing.T) {
	e := setupTestEngine(t)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/unknown-agent", "GET", "/budget/read", "")
	if d.Action != ActionDeny {
		t.Errorf("Unknown caller: expected DENY, got %s (reason: %s)", d.Action, d.Reason)
	}
	if d.Reason != "no_caller_policy" {
		t.Errorf("Unknown caller: expected reason 'no_caller_policy', got %q", d.Reason)
	}
}

func TestNoPolicyLoaded_Deny(t *testing.T) {
	store := NewPolicyStore()
	e := NewEngine(store, nil, nil, nil)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/budget/read", "")
	if d.Action != ActionDeny {
		t.Errorf("No policy: expected DENY, got %s", d.Action)
	}
	if d.Reason != "no_policy_loaded" {
		t.Errorf("No policy: expected reason 'no_policy_loaded', got %q", d.Reason)
	}
}

// ─── Path Matching Tests ───

func TestMatchPath_Exact(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/budget/read", "/budget/read", true},
		{"/budget/read", "/budget/Read", false},
		{"/budget/read", "/budget/read/", false},
		{"/budget/submit", "/budget/submit", true},
		{"/budget/submit", "/budget/sub", false},
	}
	for _, c := range cases {
		got := matchPath(c.pattern, c.path)
		if got != c.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestMatchPath_Wildcard(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/*", "/anything", true},
		{"/*", "/", true},
		{"/budget/*", "/budget/read", true},
		{"/budget/*", "/budget/submit", true},
		{"/budget/*", "/budget/foo/bar", true},
		{"/budget/*", "/budget/", true},
		{"/budget/*", "/budget", true},
		{"/budget/*", "/budgets", false},
		{"/budget/*", "/other", false},
	}
	for _, c := range cases {
		got := matchPath(c.pattern, c.path)
		if got != c.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestMatchMethod(t *testing.T) {
	cases := []struct {
		allowed []string
		method  string
		want    bool
	}{
		{[]string{"GET"}, "GET", true},
		{[]string{"GET"}, "get", true},
		{[]string{"POST"}, "GET", false},
		{[]string{"*"}, "DELETE", true},
		{[]string{"GET", "POST"}, "POST", true},
		{[]string{"GET", "POST"}, "DELETE", false},
	}
	for _, c := range cases {
		got := matchMethod(c.allowed, c.method)
		if got != c.want {
			t.Errorf("matchMethod(%v, %q) = %v, want %v", c.allowed, c.method, got, c.want)
		}
	}
}

// ─── Policy Validation Tests ───

func TestValidation_MissingVersion(t *testing.T) {
	store := NewPolicyStore()
	err := store.LoadFromBytes([]byte(`
trust_domain: "aim.microsoft.com"
default_action: deny
policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    rules:
      - path: "/*"
        methods: ["*"]
        action: allow
`))
	if err == nil {
		t.Error("Expected validation error for missing version")
	}
}

func TestValidation_WrongTrustDomain(t *testing.T) {
	store := NewPolicyStore()
	err := store.LoadFromBytes([]byte(`
version: "1.0"
trust_domain: "aim.microsoft.com"
default_action: deny
policies:
  - spiffe_id: "spiffe://other.domain/ests/bp/test-bp-oid/aid/budget-report"
    rules:
      - path: "/*"
        methods: ["*"]
        action: allow
`))
	if err == nil {
		t.Error("Expected validation error for wrong trust domain")
	}
}

func TestValidation_InvalidAction(t *testing.T) {
	store := NewPolicyStore()
	err := store.LoadFromBytes([]byte(`
version: "1.0"
trust_domain: "aim.microsoft.com"
default_action: deny
policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    rules:
      - path: "/*"
        methods: ["*"]
        action: maybe
`))
	if err == nil {
		t.Error("Expected validation error for invalid action")
	}
}

// ─── Path Normalization Bypass Tests (Issue #4) ───

func TestPathNormalization_URLEncoding(t *testing.T) {
	e := setupTestEngine(t)
	// %73ubmit decodes to "submit" — must still be denied for BudgetReport
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "POST", "/budget/%73ubmit", "")
	if d.Action != ActionDeny {
		t.Errorf("URL-encoded bypass: expected DENY, got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestPathNormalization_DotSegments(t *testing.T) {
	e := setupTestEngine(t)
	// /budget/../budget/submit should resolve to /budget/submit → denied
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "POST", "/budget/../budget/submit", "")
	if d.Action != ActionDeny {
		t.Errorf("Dot-segment bypass: expected DENY, got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestPathNormalization_DoubleSlash(t *testing.T) {
	e := setupTestEngine(t)
	// //budget/submit should collapse to /budget/submit → denied
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "POST", "//budget/submit", "")
	if d.Action != ActionDeny {
		t.Errorf("Double-slash bypass: expected DENY, got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestPathNormalization_DotSlash(t *testing.T) {
	e := setupTestEngine(t)
	// /budget/./submit should collapse to /budget/submit → denied
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "POST", "/budget/./submit", "")
	if d.Action != ActionDeny {
		t.Errorf("Dot-slash bypass: expected DENY, got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestPathNormalization_AllowedPathStillWorks(t *testing.T) {
	e := setupTestEngine(t)
	// Ensure normalization doesn't break normal allowed paths
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/budget/read", "")
	if d.Action != ActionAllow {
		t.Errorf("Normal path after normalization: expected ALLOW, got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestNormalizePath(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		{"/budget/read", "/budget/read"},
		{"/budget/%73ubmit", "/budget/submit"},
		{"/budget/../budget/submit", "/budget/submit"},
		{"//budget/submit", "/budget/submit"},
		{"/budget/./submit", "/budget/submit"},
		{"/budget/read/", "/budget/read"},
		{"", "/"},
	}
	for _, c := range cases {
		got := normalizePath(c.input)
		if got != c.want {
			t.Errorf("normalizePath(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

// ─── First-Match Semantics Test ───

// ─── SPIFFE ID Prefix Matching Tests ───

const testPrefixPolicyYAML = `
version: "2.0"
trust_domain: "aim.microsoft.com"
default_action: deny

policies:
  - spiffe_id_prefix: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    name: "budget-report"
    entra_agent_id: "entra_br_001"
    description: "Read-only access (prefix match)"
    rules:
      - path: "/budget/read"
        methods: ["GET", "POST"]
        action: allow
      - path: "/budget/submit"
        methods: ["*"]
        action: deny

  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/employee-menus"
    description: "Exact match — blocked at mTLS"
    rules:
      - path: "/*"
        methods: ["*"]
        action: deny

  - spiffe_id_prefix: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-approval"
    name: "budget-approval"
    entra_agent_id: "entra_ba_002"
    description: "Full access (prefix match)"
    rules:
      - path: "/budget/*"
        methods: ["GET", "POST"]
        action: allow
      - path: "/mgmt/*"
        methods: ["GET", "PUT"]
        action: allow
`

func setupPrefixTestEngine(t *testing.T) *Engine {
	t.Helper()
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testPrefixPolicyYAML)); err != nil {
		t.Fatalf("Failed to load prefix test policy: %v", err)
	}
	return NewEngine(store, nil, nil, nil)
}

func TestPrefix_MatchesExactLegacyID(t *testing.T) {
	e := setupPrefixTestEngine(t)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/budget/read", "")
	if d.Action != ActionAllow {
		t.Errorf("Prefix matching exact legacy ID: expected ALLOW, got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestPrefix_MatchesWithAdditionalPathSegments(t *testing.T) {
	e := setupPrefixTestEngine(t)
	// Prefix match should work when SPIFFE ID has additional path segments
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report/extra", "GET", "/budget/read", "")
	if d.Action != ActionAllow {
		t.Errorf("Prefix matching with extra segments: expected ALLOW, got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestPrefix_NoPartialSegmentMatch(t *testing.T) {
	e := setupPrefixTestEngine(t)
	// "budget-report" prefix should NOT match "budget-report-extended"
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report-extended", "GET", "/budget/read", "")
	if d.Action != ActionDeny {
		t.Errorf("Prefix partial segment: expected DENY (no_caller_policy), got %s (reason: %s)", d.Action, d.Reason)
	}
	if d.Reason != "no_caller_policy" {
		t.Errorf("Prefix partial segment: expected reason 'no_caller_policy', got %q", d.Reason)
	}
}

func TestPrefix_NoPartialPathMatch(t *testing.T) {
	// A prefix of ".../aid/budget" should not match ".../aid/budget-report"
	store := NewPolicyStore()
	err := store.LoadFromBytes([]byte(`
version: "2.0"
trust_domain: "aim.microsoft.com"
default_action: deny
policies:
  - spiffe_id_prefix: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget"
    description: "Short prefix"
    rules:
      - path: "/*"
        methods: ["*"]
        action: allow
`))
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}
	e := NewEngine(store, nil, nil, nil)
	// ".../aid/budget" should match ".../aid/budget/something" but NOT ".../aid/budget-report"
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/anything", "")
	if d.Action != ActionDeny {
		t.Errorf("Partial path: expected DENY, got %s (reason: %s)", d.Action, d.Reason)
	}
	// But it SHOULD match an exact equal
	d = e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget", "GET", "/anything", "")
	if d.Action != ActionAllow {
		t.Errorf("Exact prefix: expected ALLOW, got %s (reason: %s)", d.Action, d.Reason)
	}
	// And match with / boundary
	d = e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget/sub", "GET", "/anything", "")
	if d.Action != ActionAllow {
		t.Errorf("Prefix with / boundary: expected ALLOW, got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestExactMatch_StillWorks(t *testing.T) {
	e := setupPrefixTestEngine(t)
	// employee-menus uses exact spiffe_id — verify it still works
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/employee-menus", "GET", "/budget/read", "")
	if d.Action != ActionDeny {
		t.Errorf("Exact match: expected DENY, got %s (reason: %s)", d.Action, d.Reason)
	}
	// Exact match should NOT match with extra suffix
	d = e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/employee-menus/extra", "GET", "/budget/read", "")
	if d.Action != ActionDeny || d.Reason != "no_caller_policy" {
		t.Errorf("Exact match with /aid: expected DENY/no_caller_policy, got %s/%s", d.Action, d.Reason)
	}
}

func TestMixedPolicies_FirstMatchSemantics(t *testing.T) {
	e := setupPrefixTestEngine(t)
	// budget-approval prefix → full access
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-approval/extra", "POST", "/budget/submit", "")
	if d.Action != ActionAllow {
		t.Errorf("Mixed prefix first-match: expected ALLOW, got %s (reason: %s)", d.Action, d.Reason)
	}
	// budget-report prefix → submit denied
	d = e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report/extra", "POST", "/budget/submit", "")
	if d.Action != ActionDeny {
		t.Errorf("Mixed prefix first-match: expected DENY, got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestName_PreservedInPolicy(t *testing.T) {
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testPrefixPolicyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}
	p := store.Get()
	if p.Policies[0].Name != "budget-report" {
		t.Errorf("Name[0] not preserved: got %q, want %q", p.Policies[0].Name, "budget-report")
	}
	if p.Policies[2].Name != "budget-approval" {
		t.Errorf("Name[2] not preserved: got %q, want %q", p.Policies[2].Name, "budget-approval")
	}
}

func TestEntraAgentID_PreservedInPolicy(t *testing.T) {
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testPrefixPolicyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}
	p := store.Get()
	if p.Policies[0].EntraAgentID != "entra_br_001" {
		t.Errorf("EntraAgentID[0] not preserved: got %q, want %q", p.Policies[0].EntraAgentID, "entra_br_001")
	}
	if p.Policies[1].EntraAgentID != "" {
		t.Errorf("EntraAgentID[1] should be empty for exact-match entry: got %q", p.Policies[1].EntraAgentID)
	}
	if p.Policies[2].EntraAgentID != "entra_ba_002" {
		t.Errorf("EntraAgentID[2] not preserved: got %q, want %q", p.Policies[2].EntraAgentID, "entra_ba_002")
	}
}

func TestValidation_BothFieldsSet_Rejected(t *testing.T) {
	store := NewPolicyStore()
	err := store.LoadFromBytes([]byte(`
version: "2.0"
trust_domain: "aim.microsoft.com"
default_action: deny
policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    spiffe_id_prefix: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    rules:
      - path: "/*"
        methods: ["*"]
        action: allow
`))
	if err == nil {
		t.Error("Expected validation error when both spiffe_id and spiffe_id_prefix are set")
	}
}

func TestValidation_NeitherFieldSet_Rejected(t *testing.T) {
	store := NewPolicyStore()
	err := store.LoadFromBytes([]byte(`
version: "2.0"
trust_domain: "aim.microsoft.com"
default_action: deny
policies:
  - description: "Missing both ID fields"
    rules:
      - path: "/*"
        methods: ["*"]
        action: allow
`))
	if err == nil {
		t.Error("Expected validation error when neither spiffe_id nor spiffe_id_prefix is set")
	}
}

func TestFindCallerPolicy_ReturnsMetadata(t *testing.T) {
	e := setupPrefixTestEngine(t)
	cp := e.FindCallerPolicy("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report/extra/suffix")
	if cp == nil {
		t.Fatal("FindCallerPolicy returned nil for valid prefix match")
	}
	if cp.Name != "budget-report" {
		t.Errorf("FindCallerPolicy metadata: got Name=%q, want 'budget-report'", cp.Name)
	}
	if cp.EntraAgentID != "entra_br_001" {
		t.Errorf("FindCallerPolicy metadata: got EntraAgentID=%q, want 'entra_br_001'", cp.EntraAgentID)
	}
	if cp.Description != "Read-only access (prefix match)" {
		t.Errorf("FindCallerPolicy metadata: got Description=%q", cp.Description)
	}
}

func TestFirstMatchWins(t *testing.T) {
	store := NewPolicyStore()
	err := store.LoadFromBytes([]byte(`
version: "1.0"
trust_domain: "aim.microsoft.com"
default_action: deny
policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    rules:
      - path: "/budget/read"
        methods: ["GET"]
        action: allow
      - path: "/budget/read"
        methods: ["GET"]
        action: deny
`))
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}
	e := NewEngine(store, nil, nil, nil)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/budget/read", "")
	if d.Action != ActionAllow {
		t.Errorf("First-match: expected ALLOW (first rule), got %s", d.Action)
	}
}

// ─── JWT / OAuth Layer 3 Tests ───

// mockValidator implements oauth.JWTValidator for testing.
type mockValidator struct {
	claims *oauth.Claims
	err    error
}

func (m *mockValidator) ValidateJWT(token string) (*oauth.Claims, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.claims, nil
}

func (m *mockValidator) Status() oauth.ValidatorStatus {
	return oauth.ValidatorStatus{ConfigLoaded: true}
}

const testJWTPolicyYAML = `
version: "4.0"
trust_domain: "aim.microsoft.com"
default_action: deny

policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    description: "Read with JWT"
    rules:
      - path: "/budget/read"
        methods: ["GET"]
        action: allow
        require_jwt: true
        required_roles: ["Budget.Read"]
      - path: "/budget/submit"
        methods: ["POST"]
        action: deny

  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-approval"
    description: "Full access with JWT"
    rules:
      - path: "/budget/read"
        methods: ["GET"]
        action: allow
        require_jwt: true
        required_roles: ["Budget.Read"]
      - path: "/budget/submit"
        methods: ["POST"]
        action: allow
        require_jwt: true
        required_roles: ["Budget.Submit"]
      - path: "/mgmt/*"
        methods: ["GET", "PUT"]
        action: allow
`

func TestJWT_ValidToken_MatchingRoles_Allowed(t *testing.T) {
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testJWTPolicyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}
	v := &mockValidator{claims: &oauth.Claims{Roles: []string{"Budget.Read"}, Audience: "api://test"}}
	e := NewEngine(store, v, nil, nil)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/budget/read", "valid-token")
	if d.Action != ActionAllow {
		t.Errorf("JWT valid + matching roles: expected ALLOW, got %s (reason: %s)", d.Action, d.Reason)
	}
	if d.EnforcementLayer != "oauth" {
		t.Errorf("Expected enforcement_layer 'oauth', got %q", d.EnforcementLayer)
	}
	if !d.JWTValid {
		t.Error("Expected JWTValid to be true")
	}
}

func TestJWT_NoToken_RequireJWT_Denied(t *testing.T) {
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testJWTPolicyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}
	v := &mockValidator{claims: &oauth.Claims{Roles: []string{"Budget.Read"}}}
	e := NewEngine(store, v, nil, nil)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/budget/read", "")
	if d.Action != ActionDeny {
		t.Errorf("JWT missing (require_jwt=true): expected DENY, got %s", d.Action)
	}
	if d.EnforcementLayer != "oauth" {
		t.Errorf("Expected enforcement_layer 'oauth', got %q", d.EnforcementLayer)
	}
	if d.StatusCode != 401 {
		t.Errorf("Expected status 401, got %d", d.StatusCode)
	}
}

func TestJWT_InvalidToken_Denied(t *testing.T) {
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testJWTPolicyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}
	v := &mockValidator{err: fmt.Errorf("token expired")}
	e := NewEngine(store, v, nil, nil)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/budget/read", "expired-token")
	if d.Action != ActionDeny {
		t.Errorf("JWT invalid: expected DENY, got %s", d.Action)
	}
	if d.EnforcementLayer != "oauth" {
		t.Errorf("Expected enforcement_layer 'oauth', got %q", d.EnforcementLayer)
	}
	if d.StatusCode != 401 {
		t.Errorf("Expected status 401, got %d", d.StatusCode)
	}
}

func TestJWT_ValidToken_WrongRoles_Denied(t *testing.T) {
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testJWTPolicyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}
	// budget-approval trying /budget/submit with only Budget.Read (needs Budget.Submit).
	v := &mockValidator{claims: &oauth.Claims{Roles: []string{"Budget.Read"}, Audience: "api://test"}}
	e := NewEngine(store, v, nil, nil)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-approval", "POST", "/budget/submit", "token-with-read-only")
	if d.Action != ActionDeny {
		t.Errorf("JWT wrong roles: expected DENY, got %s (reason: %s)", d.Action, d.Reason)
	}
	if d.Reason != "insufficient_roles" {
		t.Errorf("Expected reason 'insufficient_roles', got %q", d.Reason)
	}
	if d.StatusCode != 403 {
		t.Errorf("Expected status 403, got %d", d.StatusCode)
	}
}

func TestJWT_NoValidator_RequireJWT_Denied(t *testing.T) {
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testJWTPolicyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}
	// No validator must fail closed for require_jwt rules.
	e := NewEngine(store, nil, nil, nil)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/budget/read", "")
	if d.Action != ActionDeny {
		t.Errorf("No validator + require_jwt: expected DENY, got %s (reason: %s)", d.Action, d.Reason)
	}
	if d.EnforcementLayer != "oauth" {
		t.Errorf("Expected enforcement_layer 'oauth', got %q", d.EnforcementLayer)
	}
	if d.Reason != "jwt_validator_unavailable" {
		t.Errorf("Expected reason 'jwt_validator_unavailable', got %q", d.Reason)
	}
	if d.StatusCode != 503 {
		t.Errorf("Expected status 503, got %d", d.StatusCode)
	}
}

func TestJWT_NoRequireJWT_BearerIgnored(t *testing.T) {
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testJWTPolicyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}
	v := &mockValidator{err: fmt.Errorf("should not be called")}
	e := NewEngine(store, v, nil, nil)
	// /mgmt/* has no require_jwt — bearer token should be ignored even if present.
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-approval", "GET", "/mgmt/health", "some-token")
	if d.Action != ActionAllow {
		t.Errorf("No require_jwt: expected ALLOW, got %s (reason: %s)", d.Action, d.Reason)
	}
	if d.EnforcementLayer != "rbac" {
		t.Errorf("Expected enforcement_layer 'rbac', got %q", d.EnforcementLayer)
	}
}

func TestJWT_RBAC_Deny_NoJWT_Check(t *testing.T) {
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testJWTPolicyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}
	v := &mockValidator{err: fmt.Errorf("should not be called")}
	e := NewEngine(store, v, nil, nil)
	// budget-report POST /budget/submit is action: deny in RBAC — JWT should not be checked.
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "POST", "/budget/submit", "some-token")
	if d.Action != ActionDeny {
		t.Errorf("RBAC deny: expected DENY, got %s", d.Action)
	}
	if d.EnforcementLayer != "rbac" {
		t.Errorf("Expected enforcement_layer 'rbac' (RBAC deny before JWT), got %q", d.EnforcementLayer)
	}
}

func TestHasRequiredRoles(t *testing.T) {
	cases := []struct {
		actual   []string
		required []string
		want     bool
	}{
		{[]string{"Budget.Read"}, []string{"Budget.Read"}, true},
		{[]string{"Budget.Read", "Budget.Submit"}, []string{"Budget.Submit"}, true},
		{[]string{"Budget.Read"}, []string{"Budget.Submit"}, false},
		{[]string{}, []string{"Budget.Read"}, false},
		{[]string{"Budget.Read"}, []string{}, true},
		{[]string{"Budget.Read", "Budget.Submit"}, []string{"Budget.Read", "Budget.Submit"}, true},
		{[]string{"Budget.Read"}, []string{"Budget.Read", "Budget.Submit"}, false},
	}
	for _, c := range cases {
		got := hasRequiredRoles(c.actual, c.required)
		if got != c.want {
			t.Errorf("hasRequiredRoles(%v, %v) = %v, want %v", c.actual, c.required, got, c.want)
		}
	}
}

// ─── Conditional Access (Layer 4b) Tests ───

const testCAPolicyYAML = `
version: "5.0"
trust_domain: "aim.microsoft.com"
default_action: deny

admin_governance:
  enabled: true
  target_agent_tag: finance
  risk_enforcement: sts

policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    name: "budget-report"
    description: "Read-only access to budget data"
    ca:
      agent_state: enabled
      agent_tag: finance
      blocked_risk_levels: ["high"]
    rules:
      - path: "/budget/read"
        methods: ["GET", "POST"]
        action: allow

  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/employee-menus"
    name: "employee-menus"
    description: "No tag - blocked at CA tag layer"
    ca:
      agent_state: enabled
      agent_tag: ""
      blocked_risk_levels: ["high"]
    rules:
      - path: "/*"
        methods: ["*"]
        action: deny

  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-approval"
    name: "budget-approval"
    description: "Full access + finance tag"
    ca:
      agent_state: enabled
      agent_tag: finance
      blocked_risk_levels: ["high"]
    rules:
      - path: "/budget/read"
        methods: ["GET", "POST"]
        action: allow
      - path: "/budget/submit"
        methods: ["POST"]
        action: allow

  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/disabled-agent"
    name: "disabled-agent"
    description: "Agent disabled by admin"
    ca:
      agent_state: disabled
      agent_tag: finance
      blocked_risk_levels: ["high"]
    rules:
      - path: "/*"
        methods: ["*"]
        action: allow

  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/admin-control-plane"
    name: "admin-control-plane"
    description: "Dedicated management service"
    ca:
      agent_state: enabled
      agent_tag: admin
      blocked_risk_levels: []
      skip_target_tag_check: true
    rules:
      - path: "/mgmt/*"
        methods: ["GET", "PUT"]
        action: allow
`

func setupCATestEngine(t *testing.T, riskStore *RiskStore) *Engine {
	t.Helper()
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testCAPolicyYAML)); err != nil {
		t.Fatalf("Failed to load CA test policy: %v", err)
	}
	return NewEngine(store, nil, riskStore, nil)
}

// setupCATestEngineWithCAPolicyCache creates a test engine with a CA policy cache
// that reports the given risk levels as blocked. This is needed because the engine
// no longer reads blocked_risk_levels from YAML — it uses the CA policy cache only.
func setupCATestEngineWithCAPolicyCache(t *testing.T, riskStore *RiskStore, blockedLevels []string) *Engine {
	t.Helper()
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testCAPolicyYAML)); err != nil {
		t.Fatalf("Failed to load CA test policy: %v", err)
	}
	cache := ca.NewPolicyCache(nil, 0)
	cache.SetBlockedRiskLevelsForTest(blockedLevels)
	return NewEngine(store, nil, riskStore, nil, WithCAPolicyCache(cache))
}

func TestCA_TagMatch_Allowed(t *testing.T) {
	e := setupCATestEngine(t, nil)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/budget/read", "")
	if d.Action != ActionAllow {
		t.Errorf("expected ALLOW (tag match), got %s (reason: %s, layer: %s)", d.Action, d.Reason, d.EnforcementLayer)
	}
}

func TestCA_TagMismatch_Denied(t *testing.T) {
	e := setupCATestEngine(t, nil)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/employee-menus", "GET", "/budget/read", "")
	if d.Action != ActionDeny {
		t.Errorf("expected DENY (tag mismatch), got %s", d.Action)
	}
	if d.EnforcementLayer != LayerCA {
		t.Errorf("expected enforcement_layer %q, got %q", LayerCA, d.EnforcementLayer)
	}
	if d.Reason != "agent_tag_mismatch" {
		t.Errorf("expected reason 'agent_tag_mismatch', got %q", d.Reason)
	}
	if d.CallerTag != "" {
		t.Errorf("expected empty caller tag, got %q", d.CallerTag)
	}
	if d.TargetTag != "finance" {
		t.Errorf("expected target tag 'finance', got %q", d.TargetTag)
	}
}

func TestCA_AgentDisabled_Denied(t *testing.T) {
	e := setupCATestEngine(t, nil)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/disabled-agent", "GET", "/budget/read", "")
	if d.Action != ActionDeny {
		t.Errorf("expected DENY (agent disabled), got %s", d.Action)
	}
	if d.EnforcementLayer != LayerCA {
		t.Errorf("expected enforcement_layer %q, got %q", LayerCA, d.EnforcementLayer)
	}
	if d.Reason != "agent_disabled" {
		t.Errorf("expected reason 'agent_disabled', got %q", d.Reason)
	}
}

func TestCA_RiskBlocked(t *testing.T) {
	rs := NewRiskStore()
	rs.SetRisk("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", RiskHigh)

	e := setupCATestEngineWithCAPolicyCache(t, rs, []string{"high"})
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/budget/read", "")
	if d.Action != ActionDeny {
		t.Errorf("expected DENY (high risk), got %s", d.Action)
	}
	if d.EnforcementLayer != LayerCA {
		t.Errorf("expected enforcement_layer %q, got %q", LayerCA, d.EnforcementLayer)
	}
	if d.Reason != "high_risk_agent_blocked" {
		t.Errorf("expected reason 'high_risk_agent_blocked', got %q", d.Reason)
	}
	if d.AgentRisk != RiskHigh {
		t.Errorf("expected agent_risk %q, got %q", RiskHigh, d.AgentRisk)
	}
}

func TestCA_RiskNotBlocked(t *testing.T) {
	rs := NewRiskStore()
	rs.SetRisk("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", RiskLow)

	e := setupCATestEngineWithCAPolicyCache(t, rs, []string{"high"})
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/budget/read", "")
	if d.Action != ActionAllow {
		t.Errorf("expected ALLOW (low risk), got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestCA_RiskMediumNotBlocked(t *testing.T) {
	rs := NewRiskStore()
	rs.SetRisk("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", RiskMedium)

	e := setupCATestEngineWithCAPolicyCache(t, rs, []string{"high"})
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/budget/read", "")
	if d.Action != ActionAllow {
		t.Errorf("expected ALLOW (medium risk not in blocked list), got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestCA_ControlPlaneBypassesTargetTag(t *testing.T) {
	e := setupCATestEngine(t, nil)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/admin-control-plane", "PUT", "/mgmt/agent-risk", "")
	if d.Action != ActionAllow {
		t.Errorf("expected ALLOW (control-plane tag bypass), got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestCA_RiskClearedAllowed(t *testing.T) {
	rs := NewRiskStore()
	// Set risk high, then clear to low
	rs.SetRisk("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", RiskHigh)
	rs.SetRisk("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", RiskLow)

	e := setupCATestEngineWithCAPolicyCache(t, rs, []string{"high"})
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/budget/read", "")
	if d.Action != ActionAllow {
		t.Errorf("expected ALLOW (risk cleared), got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestCA_NoAdminGovernance_SkipsCA(t *testing.T) {
	// Use v4.0 policy (no admin_governance) — CA should be skipped entirely
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testPolicyYAML)); err != nil {
		t.Fatalf("Failed to load v4.0 policy: %v", err)
	}
	e := NewEngine(store, nil, nil, nil)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/budget/read", "")
	if d.Action != ActionAllow {
		t.Errorf("expected ALLOW (no CA), got %s (reason: %s, layer: %s)", d.Action, d.Reason, d.EnforcementLayer)
	}
}

func TestCA_ThenRBAC_Deny(t *testing.T) {
	// CA passes (tag match, low risk), but RBAC denies
	e := setupCATestEngine(t, nil)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "POST", "/budget/submit", "")
	if d.Action != ActionDeny {
		t.Errorf("expected DENY (no RBAC rule match → default deny), got %s", d.Action)
	}
	if d.EnforcementLayer != LayerRBAC {
		t.Errorf("expected enforcement_layer %q (RBAC deny, not CA), got %q", LayerRBAC, d.EnforcementLayer)
	}
}

func TestCA_EvaluationOrder_DisabledBeforeRisk(t *testing.T) {
	// Agent is disabled AND has high risk — disabled should trigger first
	rs := NewRiskStore()
	rs.SetRisk("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/disabled-agent", RiskHigh)

	e := setupCATestEngine(t, rs)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/disabled-agent", "GET", "/budget/read", "")
	if d.Action != ActionDeny {
		t.Errorf("expected DENY, got %s", d.Action)
	}
	if d.Reason != "agent_disabled" {
		t.Errorf("expected reason 'agent_disabled' (checked before risk), got %q", d.Reason)
	}
}

func TestCA_EvaluationOrder_RiskBeforeTag(t *testing.T) {
	// Agent has mismatched tag AND high risk — risk should trigger first
	rs := NewRiskStore()
	rs.SetRisk("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/employee-menus", RiskHigh)

	e := setupCATestEngineWithCAPolicyCache(t, rs, []string{"high"})
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/employee-menus", "GET", "/budget/read", "")
	if d.Action != ActionDeny {
		t.Errorf("expected DENY, got %s", d.Action)
	}
	if d.Reason != "high_risk_agent_blocked" {
		t.Errorf("expected reason 'high_risk_agent_blocked' (checked before tag), got %q", d.Reason)
	}
}

// ─── TagStore Override Tests (Graph-sourced attributes) ───

func setupCATestEngineWithTagStore(t *testing.T, riskStore *RiskStore, tagStore *TagStore) *Engine {
	t.Helper()
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testCAPolicyYAML)); err != nil {
		t.Fatalf("Failed to load CA test policy: %v", err)
	}
	return NewEngine(store, nil, riskStore, tagStore)
}

func TestCA_TagStore_OverridesYAML(t *testing.T) {
	// EmployeeMenus has no tag in YAML (empty string → mismatch).
	// But if the TagStore has a "finance" tag from Graph, it should match.
	ts := NewTagStore()
	ts.SetTag("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/employee-menus", "finance")

	e := setupCATestEngineWithTagStore(t, nil, ts)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/employee-menus", "GET", "/budget/read", "")
	// Should pass CA (tag match from Graph) but then hit RBAC deny-all rule
	if d.Reason == "agent_tag_mismatch" {
		t.Errorf("TagStore should override YAML tag, but still got tag mismatch")
	}
}

func TestCA_TagStore_EmptyOverridesFinance(t *testing.T) {
	// BudgetReport has "finance" tag in YAML.
	// If Graph returns empty tag, it should override → mismatch.
	ts := NewTagStore()
	ts.SetTag("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "")

	e := setupCATestEngineWithTagStore(t, nil, ts)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/budget/read", "")
	if d.Action != ActionDeny {
		t.Errorf("expected DENY (Graph tag empty overrides YAML finance), got %s", d.Action)
	}
	if d.Reason != "agent_tag_mismatch" {
		t.Errorf("expected reason 'agent_tag_mismatch', got %q", d.Reason)
	}
}

func TestCA_TagStore_NotPresent_FallsBackToYAML(t *testing.T) {
	// TagStore exists but has no entry for budget-report.
	// Should fall back to YAML tag ("finance") and match.
	ts := NewTagStore()
	// Don't set any tag for budget-report

	e := setupCATestEngineWithTagStore(t, nil, ts)
	d := e.Evaluate("spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report", "GET", "/budget/read", "")
	if d.Action != ActionAllow {
		t.Errorf("expected ALLOW (YAML fallback tag=finance), got %s (reason: %s)", d.Action, d.Reason)
	}
}

// ─── Wildcard Path Validation Tests (Issue #29) ───

func TestValidateRulePath_ValidPaths(t *testing.T) {
	validPaths := []string{
		"/budget/read",
		"/budget/submit",
		"/*",
		"/admin/*",
		"/budget/*",
		"/a/b/c/*",
	}
	for _, p := range validPaths {
		if err := validateRulePath(p); err != nil {
			t.Errorf("validateRulePath(%q) returned error: %v", p, err)
		}
	}
}

func TestValidateRulePath_InvalidPaths(t *testing.T) {
	cases := []struct {
		path    string
		wantErr string
	}{
		{"", "rule path cannot be empty"},
		{"/budget/*/read", "wildcard '*' is only supported as a single trailing path segment"},
		{"/*/read", "wildcard '*' is only supported as a single trailing path segment"},
		{"/*foo", "wildcard '*' is only supported as a single trailing path segment"},
		{"/foo*", "wildcard '*' is only supported as a single trailing path segment"},
		{"/foo/bar*", "wildcard '*' is only supported as a single trailing path segment"},
		{"/admin/**/*", "wildcard '*' is only supported as a single trailing path segment"},
		{"/foo*/bar/*", "wildcard '*' is only supported as a single trailing path segment"},
	}
	for _, c := range cases {
		err := validateRulePath(c.path)
		if err == nil {
			t.Errorf("validateRulePath(%q): expected error containing %q, got nil", c.path, c.wantErr)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("validateRulePath(%q): expected error containing %q, got %q", c.path, c.wantErr, err.Error())
		}
	}
}

func TestValidation_MidPathWildcard_Rejected(t *testing.T) {
	store := NewPolicyStore()
	err := store.LoadFromBytes([]byte(`
version: "1.0"
trust_domain: "aim.microsoft.com"
default_action: deny
policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    rules:
      - path: "/budget/*/read"
        methods: ["GET"]
        action: allow
`))
	if err == nil {
		t.Error("Expected validation error for mid-path wildcard /budget/*/read")
	}
}

func TestValidation_TrailingWildcard_Accepted(t *testing.T) {
	store := NewPolicyStore()
	err := store.LoadFromBytes([]byte(`
version: "1.0"
trust_domain: "aim.microsoft.com"
default_action: deny
policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    rules:
      - path: "/budget/*"
        methods: ["GET"]
        action: allow
`))
	if err != nil {
		t.Errorf("Trailing wildcard should be accepted, got error: %v", err)
	}
}

// Validates that foreign trust-domain callers in federated_policies are
// authorized correctly — and completely isolated from domestic policies.

const testFederatedPolicyYAML = `
version: "5.0"
trust_domain: "aim.microsoft.com"
default_action: deny

admin_governance:
  enabled: true
  target_agent_tag: finance
  risk_enforcement: sts

policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    name: "budget-report"
    description: "Domestic read-only caller"
    ca:
      agent_state: enabled
      agent_tag: finance
    rules:
      - path: "/budget/read"
        methods: ["GET"]
        action: allow
      - path: "/budget/submit"
        methods: ["POST"]
        action: deny

federated_policies:
  - spiffe_id: "spiffe://gcp.aim.microsoft.com/ests/bp/gcp-bp-oid/aid/google-budget-reader"
    trust_domain: "gcp.aim.microsoft.com"
    name: "google-budget-reader"
    description: "Google-hosted read-only caller"
    ca:
      agent_state: enabled
      agent_tag: finance
    rules:
      - path: "/budget/read"
        methods: ["GET"]
        action: allow
      - path: "/budget/submit"
        methods: ["*"]
        action: deny
`

func setupFederatedTestEngine(t *testing.T) *Engine {
	t.Helper()
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testFederatedPolicyYAML)); err != nil {
		t.Fatalf("Failed to load federated test policy: %v", err)
	}
	return NewEngine(store, nil, nil, nil)
}

// TestFederated_AllowedPath verifies the happy path for a Google caller.
func TestFederated_AllowedPath(t *testing.T) {
	e := setupFederatedTestEngine(t)
	d := e.Evaluate(
		"spiffe://gcp.aim.microsoft.com/ests/bp/gcp-bp-oid/aid/google-budget-reader",
		"GET", "/budget/read", "",
	)
	if d.Action != ActionAllow {
		t.Errorf("Federated happy path: expected ALLOW, got %s (reason: %s, layer: %s)", d.Action, d.Reason, d.EnforcementLayer)
	}
}

// TestFederated_DeniedPath verifies that the federated caller is denied on a disallowed path.
func TestFederated_DeniedPath(t *testing.T) {
	e := setupFederatedTestEngine(t)
	d := e.Evaluate(
		"spiffe://gcp.aim.microsoft.com/ests/bp/gcp-bp-oid/aid/google-budget-reader",
		"POST", "/budget/submit", "",
	)
	if d.Action != ActionDeny {
		t.Errorf("Federated denied path: expected DENY, got %s (reason: %s)", d.Action, d.Reason)
	}
}

// TestFederated_DomesticCallerUnaffected verifies existing domestic policies still work.
func TestFederated_DomesticCallerUnaffected(t *testing.T) {
	e := setupFederatedTestEngine(t)
	d := e.Evaluate(
		"spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report",
		"GET", "/budget/read", "",
	)
	if d.Action != ActionAllow {
		t.Errorf("Domestic caller regression: expected ALLOW, got %s (reason: %s)", d.Action, d.Reason)
	}
}

// TestFederated_UnknownForeignID returns no_caller_policy (not a domestic or federated match).
func TestFederated_UnknownForeignID(t *testing.T) {
	e := setupFederatedTestEngine(t)
	d := e.Evaluate(
		"spiffe://gcp.aim.microsoft.com/ests/bp/gcp-bp-oid/aid/unknown-agent",
		"GET", "/budget/read", "",
	)
	if d.Action != ActionDeny {
		t.Errorf("Unknown foreign ID: expected DENY, got %s", d.Action)
	}
	if d.Reason != "no_caller_policy" {
		t.Errorf("Unknown foreign ID: expected reason 'no_caller_policy', got %q", d.Reason)
	}
}

// TestFederated_DomesticIDNotMatchedByFederatedEntry ensures that a domestic SPIFFE ID
// does NOT accidentally match a federated entry (and vice-versa for foreign IDs).
func TestFederated_DomesticIDNotMatchedByFederatedEntry(t *testing.T) {
	e := setupFederatedTestEngine(t)
	// A domestic ID should NOT be matched against federated_policies
	d := e.Evaluate(
		"spiffe://aim.microsoft.com/ests/bp/gcp-bp-oid/aid/google-budget-reader",
		"GET", "/budget/read", "",
	)
	// No domestic or federated policy matches this ID
	if d.Reason != "no_caller_policy" {
		t.Errorf("Domestic ID should not match federated entry: got reason %q", d.Reason)
	}
}

// TestFederated_ParsesCorrectly verifies the YAML round-trip.
func TestFederated_ParsesCorrectly(t *testing.T) {
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testFederatedPolicyYAML)); err != nil {
		t.Fatalf("Failed to load federated policy: %v", err)
	}
	p := store.Get()
	if len(p.FederatedPolicies) != 1 {
		t.Fatalf("Expected 1 federated policy, got %d", len(p.FederatedPolicies))
	}
	cp := p.FederatedPolicies[0]
	if cp.TrustDomain != "gcp.aim.microsoft.com" {
		t.Errorf("TrustDomain not preserved: got %q", cp.TrustDomain)
	}
	if cp.Name != "google-budget-reader" {
		t.Errorf("Name not preserved: got %q", cp.Name)
	}
	if cp.SpiffeID != "spiffe://gcp.aim.microsoft.com/ests/bp/gcp-bp-oid/aid/google-budget-reader" {
		t.Errorf("SpiffeID not preserved: got %q", cp.SpiffeID)
	}
}

// TestFederated_FindCallerPolicy_ReturnsFederatedEntry via the public wrapper.
func TestFederated_FindCallerPolicy_ReturnsFederatedEntry(t *testing.T) {
	e := setupFederatedTestEngine(t)
	cp := e.FindCallerPolicy("spiffe://gcp.aim.microsoft.com/ests/bp/gcp-bp-oid/aid/google-budget-reader")
	if cp == nil {
		t.Fatal("FindCallerPolicy returned nil for a valid federated SPIFFE ID")
	}
	if cp.TrustDomain != "gcp.aim.microsoft.com" {
		t.Errorf("FindCallerPolicy: wrong TrustDomain %q", cp.TrustDomain)
	}
	if cp.Name != "google-budget-reader" {
		t.Errorf("FindCallerPolicy: wrong Name %q", cp.Name)
	}
}

// TestFederated_Validation_MissingTrustDomain ensures missing trust_domain is rejected.
func TestFederated_Validation_MissingTrustDomain(t *testing.T) {
	store := NewPolicyStore()
	err := store.LoadFromBytes([]byte(`
version: "5.0"
trust_domain: "aim.microsoft.com"
default_action: deny
policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    rules:
      - path: "/*"
        methods: ["*"]
        action: allow
federated_policies:
  - spiffe_id: "spiffe://gcp.aim.microsoft.com/ests/bp/gcp-bp-oid/aid/google-budget-reader"
    name: "google-budget-reader"
    rules:
      - path: "/*"
        methods: ["*"]
        action: allow
`))
	if err == nil {
		t.Error("Expected validation error for missing trust_domain in federated entry")
	}
}

// TestFederated_Validation_SpiffeIDPrefixRejected ensures prefix match is disallowed.
func TestFederated_Validation_SpiffeIDPrefixRejected(t *testing.T) {
	store := NewPolicyStore()
	err := store.LoadFromBytes([]byte(`
version: "5.0"
trust_domain: "aim.microsoft.com"
default_action: deny
policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    rules:
      - path: "/*"
        methods: ["*"]
        action: allow
federated_policies:
  - spiffe_id_prefix: "spiffe://gcp.aim.microsoft.com/ests/bp/"
    trust_domain: "gcp.aim.microsoft.com"
    name: "google-budget-reader"
    rules:
      - path: "/*"
        methods: ["*"]
        action: allow
`))
	if err == nil {
		t.Error("Expected validation error: spiffe_id_prefix disallowed in federated_policies")
	}
}

// TestFederated_Validation_SpiffeIDMismatchesTrustDomain ensures the SPIFFE ID
// must belong to the declared per-entry trust_domain.
func TestFederated_Validation_SpiffeIDMismatchesTrustDomain(t *testing.T) {
	store := NewPolicyStore()
	err := store.LoadFromBytes([]byte(`
version: "5.0"
trust_domain: "aim.microsoft.com"
default_action: deny
policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    rules:
      - path: "/*"
        methods: ["*"]
        action: allow
federated_policies:
  - spiffe_id: "spiffe://gcp.aim.microsoft.com/ests/bp/gcp-bp-oid/aid/reader"
    trust_domain: "other.domain.com"
    name: "mismatched-entry"
    rules:
      - path: "/*"
        methods: ["*"]
        action: allow
`))
	if err == nil {
		t.Error("Expected validation error: SPIFFE ID does not match declared trust_domain")
	}
}

// TestFederated_Validation_JWTOnly_NoSpiffeIDRequired ensures jwt_only entries pass
// validation without a spiffe_id (future-compatibility for ServiceNow-style callers).
func TestFederated_Validation_JWTOnly_Rejected(t *testing.T) {
	store := NewPolicyStore()
	err := store.LoadFromBytes([]byte(`
version: "5.0"
trust_domain: "aim.microsoft.com"
default_action: deny
policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    rules:
      - path: "/*"
        methods: ["*"]
        action: allow
federated_policies:
  - jwt_only: true
    trust_domain: "my-servicenow.service-now.com"
    name: "servicenow-caller"
    rules:
      - path: "/budget/read"
        methods: ["GET"]
        action: allow
`))
	if err == nil {
		t.Error("jwt_only federated entry should be rejected, but validation passed")
	}
}

// TestFederated_CA_AgentDisabled verifies that CA kill-switch works on federated callers.
func TestFederated_CA_AgentDisabled(t *testing.T) {
	store := NewPolicyStore()
	err := store.LoadFromBytes([]byte(`
version: "5.0"
trust_domain: "aim.microsoft.com"
default_action: deny

admin_governance:
  enabled: true
  target_agent_tag: finance
  risk_enforcement: sts

policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    name: "budget-report"
    ca:
      agent_state: enabled
      agent_tag: finance
    rules:
      - path: "/budget/read"
        methods: ["GET"]
        action: allow

federated_policies:
  - spiffe_id: "spiffe://gcp.aim.microsoft.com/ests/bp/gcp-bp-oid/aid/google-budget-reader"
    trust_domain: "gcp.aim.microsoft.com"
    name: "google-budget-reader"
    ca:
      agent_state: disabled
      agent_tag: finance
    rules:
      - path: "/budget/read"
        methods: ["GET"]
        action: allow
`))
	if err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}
	e := NewEngine(store, nil, nil, nil)
	d := e.Evaluate(
		"spiffe://gcp.aim.microsoft.com/ests/bp/gcp-bp-oid/aid/google-budget-reader",
		"GET", "/budget/read", "",
	)
	if d.Action != ActionDeny {
		t.Errorf("Federated CA disabled: expected DENY, got %s", d.Action)
	}
	if d.Reason != "agent_disabled" {
		t.Errorf("Federated CA disabled: expected reason 'agent_disabled', got %q", d.Reason)
	}
	if d.EnforcementLayer != LayerCA {
		t.Errorf("Federated CA disabled: expected layer %q, got %q", LayerCA, d.EnforcementLayer)
	}
}

// TestFederated_EnrichFromEnv updates EntraAgentID for a federated entry.
func TestFederated_EnrichFromEnv(t *testing.T) {
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testFederatedPolicyYAML)); err != nil {
		t.Fatalf("Failed to load federated test policy: %v", err)
	}
	t.Setenv("ENTRA_ID_GOOGLE_BUDGET_READER", "gcp-agent-entra-oid-123")
	store.EnrichFromEnv()
	p := store.Get()
	if len(p.FederatedPolicies) != 1 {
		t.Fatalf("Expected 1 federated policy after enrichment, got %d", len(p.FederatedPolicies))
	}
	if p.FederatedPolicies[0].EntraAgentID != "gcp-agent-entra-oid-123" {
		t.Errorf("EntraAgentID not enriched: got %q", p.FederatedPolicies[0].EntraAgentID)
	}
	// Verify SPIFFE_PREFIX env var does NOT affect federated policies
	t.Setenv("SPIFFE_PREFIX_GOOGLE_BUDGET_READER", "spiffe://aim.microsoft.com/should-not-override/")
	store.EnrichFromEnv()
	p = store.Get()
	if p.FederatedPolicies[0].SpiffeIDPrefix != "" {
		t.Errorf("SPIFFE_PREFIX_* should not affect federated policies, got prefix %q", p.FederatedPolicies[0].SpiffeIDPrefix)
	}
	if p.FederatedPolicies[0].SpiffeID == "" {
		t.Error("SPIFFE_PREFIX_* must not clear federated SpiffeID")
	}
}

// TestFederated_Validation_CrossListNameCollision verifies that a federated policy
// name colliding with a domestic policy name is rejected.
func TestFederated_Validation_CrossListNameCollision(t *testing.T) {
	store := NewPolicyStore()
	err := store.LoadFromBytes([]byte(`
version: "5.0"
trust_domain: "aim.microsoft.com"
default_action: deny
policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    name: "shared-name"
    rules:
      - path: "/*"
        methods: ["*"]
        action: allow
federated_policies:
  - spiffe_id: "spiffe://gcp.aim.microsoft.com/ests/bp/gcp-bp-oid/aid/reader"
    trust_domain: "gcp.aim.microsoft.com"
    name: "shared-name"
    rules:
      - path: "/budget/read"
        methods: ["GET"]
        action: allow
`))
	if err == nil {
		t.Error("cross-list name collision should be rejected, but validation passed")
	}
}

// TestFederated_EmptyRules_Deny verifies that a federated entry with no matching
// rules falls through to the default deny action.
func TestFederated_EmptyRules_Deny(t *testing.T) {
	store := NewPolicyStore()
	err := store.LoadFromBytes([]byte(`
version: "5.0"
trust_domain: "aim.microsoft.com"
default_action: deny
policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/budget-report"
    rules:
      - path: "/*"
        methods: ["*"]
        action: allow
federated_policies:
  - spiffe_id: "spiffe://gcp.aim.microsoft.com/ests/bp/gcp-bp-oid/aid/reader"
    trust_domain: "gcp.aim.microsoft.com"
    name: "empty-rules-caller"
    rules: []
`))
	if err != nil {
		t.Fatalf("Policy with empty federated rules should load: %v", err)
	}
	e := NewEngine(store, nil, nil, nil)
	d := e.Evaluate(
		"spiffe://gcp.aim.microsoft.com/ests/bp/gcp-bp-oid/aid/reader",
		"GET", "/budget/read", "",
	)
	if d.Action != ActionDeny {
		t.Errorf("Federated empty rules: expected DENY, got %s (reason: %s)", d.Action, d.Reason)
	}
	if d.Reason != "no_matching_rule" {
		t.Errorf("Federated empty rules: expected reason 'no_matching_rule', got %q", d.Reason)
	}
}

// ─── Tag Evaluation Tests (Phase 4) ───

const testTagPolicyYAML = `
version: "1.0"
trust_domain: "aim.microsoft.com"
default_action: deny
admin_governance:
  enabled: false
policies:
  - spiffe_id: "spiffe://aim.microsoft.com/ests/bp/test-bp-oid/aid/placeholder"
    rules:
      - path: "/*"
        methods: ["*"]
        action: allow
federated_policies:
  - spiffe_id: "spiffe://aim.microsoft.com/agent/github-budget-reader"
    trust_domain: "aim.microsoft.com"
    name: "github-budget-reader"
    entra_agent_id: "github-agent-oid"
    description: "GitHub Actions runner"
    ca:
      agent_state: enabled
      agent_tag: finance
      skip_target_tag_check: true
    rules:
      - path: "/budget/read"
        methods: ["GET", "POST"]
        action: allow
        require_jwt: true
        required_roles: ["Budget.Read"]
        required_tags:
          github_repo: "microsoft/identity-spiffe"
      - path: "/budget/any"
        methods: ["GET"]
        action: allow
        require_jwt: true
        required_roles: ["Budget.Read"]
`

func setupTagTestEngine(t *testing.T) *Engine {
	t.Helper()
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testTagPolicyYAML)); err != nil {
		t.Fatalf("failed to load tag test policy: %v", err)
	}
	mockVal := &mockValidator{
		claims: &oauth.Claims{
			Issuer:   "https://login.microsoftonline.com/tenant-id/v2.0",
			Audience: "api://test",
			Roles:    []string{"Budget.Read"},
			CustomClaims: map[string]string{
				"github_repo":         "microsoft/identity-spiffe",
				"github_workflow_ref": "microsoft/identity-spiffe/.github/workflows/deploy.yml@refs/heads/main",
			},
		},
	}
	return NewEngine(store, mockVal, nil, nil)
}

func TestTag_MatchingClaims_Allowed(t *testing.T) {
	engine := setupTagTestEngine(t)
	d := engine.Evaluate(
		"spiffe://aim.microsoft.com/agent/github-budget-reader",
		"GET", "/budget/read", "valid-token",
	)
	if d.Action != ActionAllow {
		t.Errorf("expected allow, got %s: %s", d.Action, d.Reason)
	}
	if d.CustomClaims["github_repo"] != "microsoft/identity-spiffe" {
		t.Errorf("expected custom claims to be populated, got %v", d.CustomClaims)
	}
}

func TestTag_MismatchedClaims_Denied(t *testing.T) {
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testTagPolicyYAML)); err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}
	mockVal := &mockValidator{
		claims: &oauth.Claims{
			Issuer:   "https://login.microsoftonline.com/tenant-id/v2.0",
			Audience: "api://test",
			Roles:    []string{"Budget.Read"},
			CustomClaims: map[string]string{
				"github_repo": "attacker/malicious-repo",
			},
		},
	}
	engine := NewEngine(store, mockVal, nil, nil)
	d := engine.Evaluate(
		"spiffe://aim.microsoft.com/agent/github-budget-reader",
		"GET", "/budget/read", "valid-token",
	)
	if d.Action != ActionDeny {
		t.Errorf("expected deny for wrong repo, got %s", d.Action)
	}
	if d.Reason != "tag_mismatch" {
		t.Errorf("expected tag_mismatch reason, got %s", d.Reason)
	}
}

func TestTag_MissingClaim_Denied(t *testing.T) {
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testTagPolicyYAML)); err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}
	mockVal := &mockValidator{
		claims: &oauth.Claims{
			Issuer:       "https://login.microsoftonline.com/tenant-id/v2.0",
			Audience:     "api://test",
			Roles:        []string{"Budget.Read"},
			CustomClaims: map[string]string{},
		},
	}
	engine := NewEngine(store, mockVal, nil, nil)
	d := engine.Evaluate(
		"spiffe://aim.microsoft.com/agent/github-budget-reader",
		"GET", "/budget/read", "valid-token",
	)
	if d.Action != ActionDeny {
		t.Errorf("expected deny for missing tag, got %s", d.Action)
	}
	if d.Reason != "missing_required_tag" {
		t.Errorf("expected missing_required_tag reason, got %s", d.Reason)
	}
}

func TestTag_NoRequiredTags_Allowed(t *testing.T) {
	engine := setupTagTestEngine(t)
	// /budget/any has no required_tags — should allow with just roles
	d := engine.Evaluate(
		"spiffe://aim.microsoft.com/agent/github-budget-reader",
		"GET", "/budget/any", "valid-token",
	)
	if d.Action != ActionAllow {
		t.Errorf("expected allow for rule without required_tags, got %s: %s", d.Action, d.Reason)
	}
}

func TestTag_NilCustomClaims_Denied(t *testing.T) {
	store := NewPolicyStore()
	if err := store.LoadFromBytes([]byte(testTagPolicyYAML)); err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}
	mockVal := &mockValidator{
		claims: &oauth.Claims{
			Issuer:   "https://login.microsoftonline.com/tenant-id/v2.0",
			Audience: "api://test",
			Roles:    []string{"Budget.Read"},
			// CustomClaims intentionally nil
		},
	}
	engine := NewEngine(store, mockVal, nil, nil)
	d := engine.Evaluate(
		"spiffe://aim.microsoft.com/agent/github-budget-reader",
		"GET", "/budget/read", "valid-token",
	)
	if d.Action != ActionDeny {
		t.Errorf("expected deny when CustomClaims is nil, got %s", d.Action)
	}
	if d.Reason != "missing_required_tag" {
		t.Errorf("expected missing_required_tag, got %s", d.Reason)
	}
}
