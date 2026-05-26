package rbac

import (
	"fmt"
	"log"
	"net/url"
	"path"
	"strings"

	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/ca"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/oauth"
)

// Decision captures the outcome of an RBAC evaluation.
type Decision struct {
	Action           Action   `json:"action"`
	Reason           string   `json:"reason"`
	MatchedRule      *Rule    `json:"-"`
	EnforcementLayer string   `json:"enforcement_layer"`
	StatusCode       int      `json:"status_code,omitempty"`
	JWTPresent       bool     `json:"jwt_present,omitempty"`
	JWTValid         bool     `json:"jwt_valid,omitempty"`
	JWTAudience      string   `json:"jwt_audience,omitempty"`
	JWTRoles         []string `json:"jwt_roles,omitempty"`
	JWTError         string   `json:"jwt_error,omitempty"`
	// CA enforcement fields (Layer 4b)
	AgentRisk string `json:"agent_risk,omitempty"`
	CallerTag string `json:"caller_tag,omitempty"`
	TargetTag string `json:"target_tag,omitempty"`
	// Request-scoped claims from JWT (e.g., GitHub provenance)
	CustomClaims map[string]string `json:"custom_claims,omitempty"`
}

// Engine evaluates RBAC policies against incoming requests.
type Engine struct {
	store         *PolicyStore
	validator     oauth.JWTValidator
	riskStore     *RiskStore
	tagStore      *TagStore
	caPolicyCache *ca.PolicyCache
}

// NewEngine creates an RBAC evaluation engine backed by the given store.
// The validator is optional — if nil, require_jwt rules fail closed
// (denied with 503 "jwt_validator_unavailable").
// The riskStore is optional — if nil, risk checks are skipped.
// The tagStore is optional — if nil, tags are read from YAML policy only.
// The caPolicyCache is optional — if nil, risk enforcement is skipped (no YAML fallback).
func NewEngine(store *PolicyStore, validator oauth.JWTValidator, riskStore *RiskStore, tagStore *TagStore, opts ...EngineOption) *Engine {
	e := &Engine{store: store, validator: validator, riskStore: riskStore, tagStore: tagStore}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// EngineOption configures optional Engine components.
type EngineOption func(*Engine)

// WithCAPolicyCache sets the CA policy cache for Graph-sourced risk enforcement.
func WithCAPolicyCache(cache *ca.PolicyCache) EngineOption {
	return func(e *Engine) {
		e.caPolicyCache = cache
	}
}

// Evaluate checks whether the given (spiffeID, method, path, bearerToken) tuple is allowed.
//
// Evaluation order:
//  1. Find the CallerPolicy matching spiffeID. If none → default_action.
//  2. Within the matched CallerPolicy, evaluate rules in order. First match wins.
//  3. If the matched rule has require_jwt: true, validate the JWT (Layer 3).
//  4. If no rule matches → default_action.
func (e *Engine) Evaluate(spiffeID, method, requestPath, bearerToken string) Decision {
	// Normalize the request path to prevent bypasses via URL encoding,
	// dot segments, double slashes, or trailing slash mismatches.
	// This ensures the RBAC engine evaluates the same logical path
	// that the downstream application (FastAPI) will route.
	requestPath = normalizePath(requestPath)

	policy := e.store.Get()
	if policy == nil {
		// No policy loaded → deny by default (fail-closed).
		log.Printf("[RBAC] No policy loaded, denying %s %s %s", spiffeID, method, requestPath)
		return Decision{
			Action:           ActionDeny,
			Reason:           "no_policy_loaded",
			EnforcementLayer: LayerRBAC,
			StatusCode:       403,
		}
	}

	// Step 1: Find caller policy (supports exact match and prefix match).
	callerPolicy := findCallerPolicy(policy, spiffeID)

	if callerPolicy == nil {
		return Decision{
			Action:           policy.DefaultAction,
			Reason:           "no_caller_policy",
			EnforcementLayer: LayerRBAC,
			StatusCode:       403,
		}
	}

	// Step 2: Layer 4b — Conditional Access (admin governance).
	// CA evaluation runs BEFORE RBAC rules because admin authority
	// supersedes developer-defined policies.
	if caDecision := e.evaluateCA(policy, callerPolicy, spiffeID); caDecision != nil {
		return *caDecision
	}

	// Step 3: Evaluate rules in order (first match wins).
	for i := range callerPolicy.Rules {
		r := &callerPolicy.Rules[i]
		if matchPath(r.Path, requestPath) && matchMethod(r.Methods, method) {
			decision := Decision{
				Action:           r.Action,
				Reason:           "matched_rule",
				MatchedRule:      r,
				EnforcementLayer: LayerRBAC,
				JWTPresent:       bearerToken != "",
			}

			// If RBAC denies, no need to check JWT.
			if r.Action == ActionDeny {
				decision.StatusCode = 403
				return decision
			}

			// Step 3: Layer 3 — JWT validation. Rules that require JWT must fail closed
			// if the validator is unavailable due to config or startup issues.
			if r.RequireJWT {
				if e.validator == nil {
					decision.Action = ActionDeny
					decision.Reason = "jwt_validator_unavailable"
					decision.EnforcementLayer = LayerOAuth
					decision.StatusCode = 503
					decision.JWTError = "JWT validator unavailable for require_jwt rule"
					return decision
				}
				return e.evaluateJWT(decision, bearerToken, r.RequiredRoles)
			}

			return decision
		}
	}

	// Step 4: No rule matched.
	return Decision{
		Action:           policy.DefaultAction,
		Reason:           "no_matching_rule",
		EnforcementLayer: LayerRBAC,
		StatusCode:       403,
		JWTPresent:       bearerToken != "",
	}
}

// evaluateJWT performs Layer 3 (OAuth/JWT) enforcement.
// Called when a matched rule has require_jwt: true and a validator is configured.
func (e *Engine) evaluateJWT(decision Decision, bearerToken string, requiredRoles []string) Decision {
	if bearerToken == "" {
		decision.Action = ActionDeny
		decision.Reason = "jwt_required"
		decision.EnforcementLayer = LayerOAuth
		decision.StatusCode = 401
		decision.JWTError = "JWT required but not provided"
		return decision
	}

	claims, err := e.validator.ValidateJWT(bearerToken)
	if err != nil {
		decision.Action = ActionDeny
		decision.Reason = "jwt_invalid"
		decision.EnforcementLayer = LayerOAuth
		decision.StatusCode = 401
		decision.JWTError = err.Error()
		return decision
	}

	decision.JWTValid = true
	decision.JWTAudience = claims.Audience
	decision.JWTRoles = claims.Roles

	// Check required roles (if specified in the rule).
	if len(requiredRoles) > 0 && !hasRequiredRoles(claims.Roles, requiredRoles) {
		decision.Action = ActionDeny
		decision.Reason = "insufficient_roles"
		decision.EnforcementLayer = LayerOAuth
		decision.StatusCode = 403
		return decision
	}

	// Populate custom claims from JWT for audit trail
	decision.CustomClaims = claims.CustomClaims

	// Check required_tags if specified on the matched rule.
	// This enables per-repo/per-workflow authorization for federated callers.
	if decision.MatchedRule != nil && len(decision.MatchedRule.RequiredTags) > 0 {
		for tagKey, tagValue := range decision.MatchedRule.RequiredTags {
			actual, ok := claims.CustomClaims[tagKey]
			if !ok {
				decision.Action = ActionDeny
				decision.Reason = "missing_required_tag"
				decision.EnforcementLayer = LayerOAuth
				decision.StatusCode = 403
				decision.JWTError = fmt.Sprintf("required tag %q not present in JWT claims", tagKey)
				return decision
			}
			if actual != tagValue {
				decision.Action = ActionDeny
				decision.Reason = "tag_mismatch"
				decision.EnforcementLayer = LayerOAuth
				decision.StatusCode = 403
				decision.JWTError = fmt.Sprintf("tag %q: expected %q, got %q", tagKey, tagValue, actual)
				return decision
			}
		}
	}

	// All three layers passed.
	decision.EnforcementLayer = LayerOAuth
	return decision
}

// hasRequiredRoles checks if actualRoles contains all requiredRoles.
func hasRequiredRoles(actualRoles, requiredRoles []string) bool {
	roleSet := make(map[string]bool, len(actualRoles))
	for _, r := range actualRoles {
		roleSet[r] = true
	}
	for _, required := range requiredRoles {
		if !roleSet[required] {
			return false
		}
	}
	return true
}

// matchPath checks if the request path matches the rule's path pattern.
//
// Supported patterns:
//   - Exact match: "/execute" matches only "/execute"
//   - Wildcard suffix: "/admin/*" matches "/admin/", "/admin/data", "/admin/foo/bar",
//     and also "/admin" (without trailing slash) for convenience.
//   - Global wildcard: "/*" matches everything
//
// Edge case: "/budget/*" also matches "/budget" (no trailing slash). This is
// intentional — it prevents requests from slipping through when the trailing
// slash is stripped by normalizePath. Policy authors who want to match ONLY
// sub-paths should use exact-match rules for the bare path.
//
// IMPORTANT: Wildcards are only supported at the END of a path pattern (e.g.,
// "/admin/*"). Wildcards in the middle (e.g., "/budget/*/read") are NOT
// supported — the "*" would be treated as a literal character, silently
// failing to match intended paths. Policy loading validates this constraint;
// see validateRulePath in policy.go.
func matchPath(pattern, requestPath string) bool {
	// Global wildcard.
	if pattern == "/*" {
		return true
	}

	// Wildcard suffix: "/admin/*" → check prefix "/admin/".
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*") // "/admin/"
		return strings.HasPrefix(requestPath, prefix) || requestPath == strings.TrimSuffix(prefix, "/")
	}

	// Exact match.
	return pattern == requestPath
}

// normalizePath canonicalizes a request path to prevent RBAC bypasses.
// It URL-decodes, resolves dot segments, collapses double slashes,
// and strips trailing slashes (except for root "/").
func normalizePath(p string) string {
	// Step 1: URL-decode (e.g., %73 → s, %2F → /).
	decoded, err := url.PathUnescape(p)
	if err == nil {
		p = decoded
	}

	// Step 2: Resolve dot segments and collapse double slashes.
	// path.Clean: "//a" → "/a", "/a/../b" → "/b", "/a/./b" → "/a/b"
	p = path.Clean(p)

	// path.Clean returns "." for empty input; force root.
	if p == "." || p == "" {
		return "/"
	}

	return p
}

// matchCallerSpiffeID checks whether the given SPIFFE ID matches a CallerPolicy.
// Supports two modes:
//   - Exact match: CallerPolicy.SpiffeID must equal spiffeID exactly.
//   - Prefix match: spiffeID must equal the prefix OR start with prefix + "/".
//     The "/" boundary prevents "budget-report" from matching "budget-report-extended".
func matchCallerSpiffeID(cp *CallerPolicy, spiffeID string) bool {
	if cp.SpiffeID != "" {
		return cp.SpiffeID == spiffeID
	}
	if cp.SpiffeIDPrefix != "" {
		if spiffeID == cp.SpiffeIDPrefix {
			return true
		}
		return strings.HasPrefix(spiffeID, cp.SpiffeIDPrefix+"/")
	}
	return false
}

// findCallerPolicy returns the first CallerPolicy matching the given SPIFFE ID.
// Searches domestic Policies first, then FederatedPolicies. Returns nil if
// no match is found in either slice.
func findCallerPolicy(policy *Policy, spiffeID string) *CallerPolicy {
	for i := range policy.Policies {
		if matchCallerSpiffeID(&policy.Policies[i], spiffeID) {
			cp := &policy.Policies[i]
			name := cp.Name
			if name == "" {
				name = fmt.Sprintf("policy[%d]", i)
			}
			if cp.SpiffeIDPrefix != "" {
				log.Printf("[RBAC] Prefix match: caller %s matched policy %q (prefix: %s)", spiffeID, name, cp.SpiffeIDPrefix)
			} else {
				log.Printf("[RBAC] Exact match: caller %s matched policy %q", spiffeID, name)
			}
			return cp
		}
	}
	// Fall through to federated policies (cross-cloud callers with foreign trust domains).
	// These entries use exact SPIFFE IDs only — no prefix matching for foreign trust domains.
	for i := range policy.FederatedPolicies {
		fp := &policy.FederatedPolicies[i]
		if fp.SpiffeIDPrefix != "" {
			log.Printf("[RBAC] BUG: federated_policy[%d] has SpiffeIDPrefix set — skipping", i)
			continue
		}
		if matchCallerSpiffeID(fp, spiffeID) {
			cp := fp
			name := cp.Name
			if name == "" {
				name = fmt.Sprintf("federated_policy[%d]", i)
			}
			log.Printf("[RBAC] Federated match: caller %s matched federated policy %q (domain: %s)", spiffeID, name, cp.TrustDomain)
			return cp
		}
	}
	return nil
}

// FindCallerPolicy returns the CallerPolicy matching the given SPIFFE ID from
// the current active policy. Returns nil if no policy is loaded or no match found.
// This is useful for gateway/audit code that needs the caller's metadata.
func (e *Engine) FindCallerPolicy(spiffeID string) *CallerPolicy {
	policy := e.store.Get()
	if policy == nil {
		return nil
	}
	return findCallerPolicy(policy, spiffeID)
}

// evaluateCA performs Layer 4b (data-plane Conditional Access) enforcement.
// This is the admin governance layer — it supersedes developer-defined RBAC.
//
// Evaluation order:
//  1. Agent state check — admin kill switch (disabled → 403)
//  2. Risk check — agentIdRiskLevels from Entra CA policy (Graph) vs current risk
//  3. Tag check — caller's agent_tag vs target's target_agent_tag
//
// Returns nil if CA passes (proceed to RBAC), or a deny Decision if blocked.
func (e *Engine) evaluateCA(policy *Policy, cp *CallerPolicy, spiffeID string) *Decision {
	if !policy.AdminGovernance.Enabled {
		return nil // CA not active, proceed to RBAC
	}

	// 4b-1: Agent state check (admin kill switch)
	if cp.CA.AgentState == "disabled" {
		log.Printf("[CA] Agent disabled: %s (%s)", spiffeID, cp.Name)
		return &Decision{
			Action:           ActionDeny,
			Reason:           "agent_disabled",
			EnforcementLayer: LayerCA,
			StatusCode:       403,
		}
	}

	// 4b-2: Risk check — CA policy from Entra Graph is the sole source of truth.
	// No YAML fallback: if Graph credentials are configured but CA policy can't be
	// read, risk enforcement is skipped (not silently using developer-authored YAML).
	if e.riskStore != nil && e.caPolicyCache != nil {
		if blockedLevels := e.caPolicyCache.GetBlockedRiskLevels(); len(blockedLevels) > 0 {
			risk := e.riskStore.GetRisk(spiffeID)
			for _, blocked := range blockedLevels {
				if risk == blocked {
					log.Printf("[CA] Agent risk blocked: %s risk=%s (blocked levels: %v, source: entra_ca_policy)", spiffeID, risk, blockedLevels)
					return &Decision{
						Action:           ActionDeny,
						Reason:           "high_risk_agent_blocked",
						EnforcementLayer: LayerCA,
						StatusCode:       403,
						AgentRisk:        risk,
					}
				}
			}
		}
	}

	// 4b-3: Tag check
	// Priority: TagStore (Graph-sourced, real Entra attributes) > YAML ca.agent_tag
	targetTag := policy.AdminGovernance.TargetAgentTag
	if targetTag != "" {
		if cp.CA.SkipTargetTagCheck {
			log.Printf("[CA] Target tag check bypassed for caller: %s (%s)", spiffeID, cp.Name)
			return nil
		}
		callerTag := cp.CA.AgentTag // fallback: YAML policy value
		tagSource := "yaml"
		if e.tagStore != nil {
			if graphTag, ok := e.tagStore.GetTag(spiffeID); ok {
				callerTag = graphTag
				tagSource = "graph"
			}
		}
		if !strings.EqualFold(callerTag, targetTag) {
			log.Printf("[CA] Agent tag mismatch: %s caller_tag=%q (source=%s) target_tag=%q", spiffeID, callerTag, tagSource, targetTag)
			return &Decision{
				Action:           ActionDeny,
				Reason:           "agent_tag_mismatch",
				EnforcementLayer: LayerCA,
				StatusCode:       403,
				CallerTag:        callerTag,
				TargetTag:        targetTag,
			}
		}
		log.Printf("[CA] Agent tag match: %s caller_tag=%q (source=%s) target_tag=%q", spiffeID, callerTag, tagSource, targetTag)
	}

	return nil // CA passed, proceed to RBAC
}

// matchMethod checks if the request method matches any in the rule's list.
// Wildcard "*" matches all methods.
func matchMethod(allowedMethods []string, requestMethod string) bool {
	reqUpper := strings.ToUpper(requestMethod)
	for _, m := range allowedMethods {
		if m == "*" || strings.ToUpper(m) == reqUpper {
			return true
		}
	}
	return false
}
