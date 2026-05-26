// Package rbac implements RBAC policy evaluation for the SPIFFE sidecar gateway.
//
// Policies map (SPIFFE ID, HTTP method, URL path) → allow/deny decisions.
// This provides application-layer authorization on top of transport-layer mTLS,
// enabling fine-grained runtime segmentation between agents.
package rbac

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Action represents an RBAC decision.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// EnforcementLayer identifies which enforcement layer produced a decision.
type EnforcementLayer = string

const (
	LayerCA    EnforcementLayer = "conditional_access"
	LayerRBAC  EnforcementLayer = "rbac"
	LayerOAuth EnforcementLayer = "oauth"
)

// Rule defines a single path/method authorization rule.
// RequireJWT and RequiredRoles enable Layer 3 (OAuth/JWT) enforcement
// when an oauth.Validator is configured on the RBAC engine.
type Rule struct {
	Path          string            `yaml:"path"           json:"path"`
	Methods       []string          `yaml:"methods"        json:"methods"`
	Action        Action            `yaml:"action"         json:"action"`
	RequireJWT    bool              `yaml:"require_jwt"    json:"require_jwt,omitempty"`
	RequiredRoles []string          `yaml:"required_roles" json:"required_roles,omitempty"`
	RequiredTags  map[string]string `yaml:"required_tags"  json:"required_tags,omitempty"`
}

// AdminGovernance defines the top-level admin governance configuration.
// This is Layer 4 — admin authority that supersedes developer policies.
// Maps to Entra Conditional Access constructs:
//   - target_agent_tag → Custom security attribute on the resource (this agent)
//   - risk_enforcement → Where risk is checked ("sts", "data_plane", or "sts_and_data_plane")
type AdminGovernance struct {
	Enabled         bool   `yaml:"enabled"            json:"enabled"`
	TargetAgentTag  string `yaml:"target_agent_tag"   json:"target_agent_tag"`
	RiskEnforcement string `yaml:"risk_enforcement"   json:"risk_enforcement"`
}

// CAPolicy defines the Conditional Access settings for a single caller.
// Maps to Entra CA constructs:
//   - agent_state → CA policy enable/disable (admin kill switch)
//   - agent_tag → Custom security attribute on the calling agent
//   - skip_target_tag_check → explicit exemption for the admin control plane
//
// NOTE: blocked_risk_levels has been removed. Risk enforcement is now driven
// exclusively by the Entra CA policy's agentIdRiskLevels condition, read from
// Graph API by the CA policy cache. No YAML fallback.
type CAPolicy struct {
	AgentState         string   `yaml:"agent_state"            json:"agent_state"`
	AgentTag           string   `yaml:"agent_tag"              json:"agent_tag"`
	BlockedRiskLevels  []string `yaml:"blocked_risk_levels"    json:"blocked_risk_levels"` // DEPRECATED: ignored by engine, kept for YAML parse compat
	SkipTargetTagCheck bool     `yaml:"skip_target_tag_check"  json:"skip_target_tag_check,omitempty"`
}

// CallerPolicy defines the RBAC rules for a single SPIFFE ID.
// Exactly one of SpiffeID (exact match) or SpiffeIDPrefix (prefix match with
// "/" boundary) must be set. Name is used for env var enrichment (e.g.,
// "budget-report" → ENTRA_ID_BUDGET_REPORT). EntraAgentID is optional
// metadata linking the policy entry to the Entra Agent Identity for auditability.
//
// TrustDomain is only used in federated_policies entries. It specifies the
// foreign SPIFFE trust domain of the caller and overrides the global trust_domain
// prefix check during validation.
//
// JWTOnly marks a caller that uses OAuth2/JWT for identity without a SPIFFE
// transport layer (e.g. ServiceNow platform agents). When true, spiffe_id is
// not required. Only valid in federated_policies entries.
type CallerPolicy struct {
	SpiffeID       string   `yaml:"spiffe_id"         json:"spiffe_id"`
	SpiffeIDPrefix string   `yaml:"spiffe_id_prefix"  json:"spiffe_id_prefix,omitempty"`
	Name           string   `yaml:"name"              json:"name,omitempty"`
	EntraAgentID   string   `yaml:"entra_agent_id"    json:"entra_agent_id,omitempty"`
	Description    string   `yaml:"description"       json:"description"`
	CA             CAPolicy `yaml:"ca"                json:"ca,omitempty"`
	Rules          []Rule   `yaml:"rules"             json:"rules"`
	TrustDomain    string   `yaml:"trust_domain"      json:"trust_domain,omitempty"`
	JWTOnly        bool     `yaml:"jwt_only"          json:"jwt_only,omitempty"`
}

// Policy is the top-level RBAC policy document.
//
// FederatedPolicies holds entries for callers from foreign SPIFFE trust domains.
// These bypass the global trust_domain prefix check; each entry must supply its
// own trust_domain. This keeps domestic and federated authorization explicitly
// separated — existing Validate() logic for Policies is completely unchanged.
type Policy struct {
	Version           string          `yaml:"version"             json:"version"`
	TrustDomain       string          `yaml:"trust_domain"        json:"trust_domain"`
	DefaultAction     Action          `yaml:"default_action"      json:"default_action"`
	AdminGovernance   AdminGovernance `yaml:"admin_governance"    json:"admin_governance"`
	Policies          []CallerPolicy  `yaml:"policies"            json:"policies"`
	FederatedPolicies []CallerPolicy  `yaml:"federated_policies"  json:"federated_policies,omitempty"`
}

// PolicyStore holds the active policy with safe concurrent access.
type PolicyStore struct {
	mu       sync.RWMutex
	policy   *Policy
	loadedAt time.Time
	version  string
}

// NewPolicyStore creates an empty store.
func NewPolicyStore() *PolicyStore {
	return &PolicyStore{}
}

// LoadFromFile reads and validates a YAML policy file.
func (ps *PolicyStore) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}
	return ps.LoadFromBytes(data)
}

// LoadFromBytes parses, validates, and atomically swaps the active policy.
func (ps *PolicyStore) LoadFromBytes(data []byte) error {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("parse policy YAML: %w", err)
	}
	if err := p.Validate(); err != nil {
		return fmt.Errorf("validate policy: %w", err)
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.policy = &p
	ps.loadedAt = time.Now().UTC()
	ps.version = p.Version
	return nil
}

// EnrichFromEnv updates policy entries with Entra Agent IDs and SPIFFE ID
// prefixes from environment variables. This allows baked-in YAML policies to
// have placeholder values that get replaced at runtime with real IDs injected
// by deploy.sh.
//
// Env var naming convention (using the Name field from each CallerPolicy):
//
//	ENTRA_ID_<UPPER_NAME>=<entra-agent-id>
//	SPIFFE_PREFIX_<UPPER_NAME>=<full-spiffe-id-prefix>
//
// where UPPER_NAME is derived from the Name field, e.g.:
//
//	name: "budget-report" → ENTRA_ID_BUDGET_REPORT, SPIFFE_PREFIX_BUDGET_REPORT
func (ps *PolicyStore) EnrichFromEnv() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.policy == nil {
		return
	}
	for i := range ps.policy.Policies {
		cp := &ps.policy.Policies[i]
		if cp.Name == "" {
			continue
		}
		envKey := strings.ToUpper(strings.ReplaceAll(cp.Name, "-", "_"))
		if v := os.Getenv("ENTRA_ID_" + envKey); v != "" {
			cp.EntraAgentID = v
		}
		if v := os.Getenv("SPIFFE_PREFIX_" + envKey); v != "" {
			cp.SpiffeIDPrefix = v
			// Maintain CallerPolicy invariant: do not keep both SpiffeID and SpiffeIDPrefix.
			cp.SpiffeID = ""
		}
	}
	// Enrich federated policies: EntraAgentID only.
	// SPIFFE_PREFIX_* env vars do NOT apply — the SPIFFE ID for federated callers
	// includes the foreign trust domain and must be set explicitly in YAML.
	for i := range ps.policy.FederatedPolicies {
		cp := &ps.policy.FederatedPolicies[i]
		if cp.Name == "" {
			continue
		}
		envKey := strings.ToUpper(strings.ReplaceAll(cp.Name, "-", "_"))
		if v := os.Getenv("ENTRA_ID_" + envKey); v != "" {
			cp.EntraAgentID = v
		}
	}
}

// Get returns a snapshot of the current policy.
func (ps *PolicyStore) Get() *Policy {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.policy
}

// LoadedAt returns when the current policy was loaded.
func (ps *PolicyStore) LoadedAt() time.Time {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.loadedAt
}

// Version returns the active policy version string.
func (ps *PolicyStore) Version() string {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.version
}

// ValidateNoDuplicatePrefixes checks that no two CallerPolicy entries share
// the same resolved SpiffeIDPrefix. Duplicate prefixes cause first-match-wins
// ambiguity: the second entry is silently unreachable. This should be called
// after EnrichFromEnv() so that env-var-overridden prefixes are checked.
func (p *Policy) ValidateNoDuplicatePrefixes() error {
	seen := make(map[string]string) // prefix → first policy name/index that used it
	for i, cp := range p.Policies {
		prefix := cp.SpiffeIDPrefix
		if prefix == "" {
			continue // exact-match entries don't collide via prefix
		}
		label := cp.Name
		if label == "" {
			label = fmt.Sprintf("policy[%d]", i)
		}
		if prev, exists := seen[prefix]; exists {
			return fmt.Errorf("duplicate spiffe_id_prefix %q: policy %q collides with %q — "+
				"set SPIFFE_PREFIX_<NAME> env vars to provide unique per-agent prefixes",
				prefix, label, prev)
		}
		seen[prefix] = label
	}
	return nil
}

// validateRulePath checks that a rule path uses wildcards correctly.
// Only trailing wildcards (e.g., "/admin/*") and the global wildcard ("/*") are
// supported. Wildcards in the middle of a path (e.g., "/budget/*/read") are NOT
// supported and would be silently treated as literal "*" characters by matchPath,
// which is almost certainly not the author's intent. This validation rejects such
// paths at load time to prevent ambiguous matching behavior.
func validateRulePath(path string) error {
	if path == "" {
		return fmt.Errorf("rule path cannot be empty")
	}
	if path == "/*" {
		return nil // global wildcard is valid
	}
	wildcardCount := strings.Count(path, "*")
	if wildcardCount == 0 {
		return nil
	}
	if wildcardCount > 1 || !strings.HasSuffix(path, "/*") {
		return fmt.Errorf("wildcard '*' is only supported as a single trailing path segment (e.g., /admin/*), got: %q", path)
	}
	return nil
}

// Validate checks that the policy is well-formed.
func (p *Policy) Validate() error {
	if p.Version == "" {
		return fmt.Errorf("version is required")
	}
	if p.TrustDomain == "" {
		return fmt.Errorf("trust_domain is required")
	}
	if p.DefaultAction != ActionAllow && p.DefaultAction != ActionDeny {
		return fmt.Errorf("default_action must be 'allow' or 'deny', got %q", p.DefaultAction)
	}
	if len(p.Policies) == 0 {
		return fmt.Errorf("at least one policy entry is required")
	}

	expectedPrefix := "spiffe://" + p.TrustDomain + "/"
	for i, cp := range p.Policies {
		hasExact := cp.SpiffeID != ""
		hasPrefix := cp.SpiffeIDPrefix != ""
		if hasExact && hasPrefix {
			return fmt.Errorf("policy[%d]: set spiffe_id or spiffe_id_prefix, not both", i)
		}
		if !hasExact && !hasPrefix {
			return fmt.Errorf("policy[%d]: one of spiffe_id or spiffe_id_prefix is required", i)
		}
		idToCheck := cp.SpiffeID
		if hasPrefix {
			idToCheck = cp.SpiffeIDPrefix
		}
		if !strings.HasPrefix(idToCheck, expectedPrefix) {
			return fmt.Errorf("policy[%d]: spiffe_id %q must be in trust domain %q (expected prefix %q)",
				i, idToCheck, p.TrustDomain, expectedPrefix)
		}
		for j, r := range cp.Rules {
			if r.Path == "" {
				return fmt.Errorf("policy[%d].rules[%d]: path is required", i, j)
			}
			if err := validateRulePath(r.Path); err != nil {
				return fmt.Errorf("policy[%d].rules[%d]: %w", i, j, err)
			}
			if len(r.Methods) == 0 {
				return fmt.Errorf("policy[%d].rules[%d]: at least one method is required", i, j)
			}
			if r.Action != ActionAllow && r.Action != ActionDeny {
				return fmt.Errorf("policy[%d].rules[%d]: action must be 'allow' or 'deny', got %q", i, j, r.Action)
			}
		}
	}

	// Validate federated_policies entries. These have a per-entry trust_domain
	// and are NOT checked against the global trust_domain prefix. Existing
	// Policies validation above is completely unchanged.
	for i, cp := range p.FederatedPolicies {
		if cp.TrustDomain == "" {
			return fmt.Errorf("federated_policies[%d]: trust_domain is required", i)
		}
		// spiffe_id_prefix is disallowed for federated entries: use exact spiffe_id.
		// Reason: we authorize one known Google caller, not a whole foreign subtree.
		if cp.SpiffeIDPrefix != "" {
			return fmt.Errorf("federated_policies[%d]: spiffe_id_prefix is not allowed; use exact spiffe_id", i)
		}
		if cp.JWTOnly {
			return fmt.Errorf("federated_policies[%d]: jwt_only is not yet supported by the RBAC engine — remove jwt_only or wait for engine support", i)
		}
		if cp.SpiffeID == "" {
			return fmt.Errorf("federated_policies[%d]: spiffe_id is required", i)
		}
		if cp.SpiffeID != "" {
			fedPrefix := "spiffe://" + cp.TrustDomain + "/"
			if !strings.HasPrefix(cp.SpiffeID, fedPrefix) {
				return fmt.Errorf("federated_policies[%d]: spiffe_id %q must be in declared trust domain %q (expected prefix %q)",
					i, cp.SpiffeID, cp.TrustDomain, fedPrefix)
			}
		}
		for j, r := range cp.Rules {
			if r.Path == "" {
				return fmt.Errorf("federated_policies[%d].rules[%d]: path is required", i, j)
			}
			if len(r.Methods) == 0 {
				return fmt.Errorf("federated_policies[%d].rules[%d]: at least one method is required", i, j)
			}
			if r.Action != ActionAllow && r.Action != ActionDeny {
				return fmt.Errorf("federated_policies[%d].rules[%d]: action must be 'allow' or 'deny', got %q", i, j, r.Action)
			}
		}
	}

	// Cross-list name uniqueness: no federated policy name may collide with a domestic one.
	namesSeen := make(map[string]string)
	for i, cp := range p.Policies {
		if cp.Name != "" {
			namesSeen[cp.Name] = fmt.Sprintf("policies[%d]", i)
		}
	}
	for i, fp := range p.FederatedPolicies {
		if fp.Name != "" {
			if prev, ok := namesSeen[fp.Name]; ok {
				return fmt.Errorf("federated_policies[%d]: name %q collides with %s", i, fp.Name, prev)
			}
		}
	}

	// Cross-list spiffe_id uniqueness: no federated spiffe_id may collide with a domestic one.
	spiffesSeen := make(map[string]string)
	for i, cp := range p.Policies {
		if cp.SpiffeID != "" {
			spiffesSeen[cp.SpiffeID] = fmt.Sprintf("policies[%d]", i)
		}
	}
	for i, fp := range p.FederatedPolicies {
		if fp.SpiffeID != "" {
			if prev, ok := spiffesSeen[fp.SpiffeID]; ok {
				return fmt.Errorf("federated_policies[%d]: spiffe_id %q collides with %s", i, fp.SpiffeID, prev)
			}
		}
	}

	return nil
}
