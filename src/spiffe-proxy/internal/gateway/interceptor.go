// Package gateway integrates the RBAC engine, HTTP inspection, structured logging,
// and management API into the existing tunnel ingress proxy.
//
// It intercepts the parsed HTTP request in the gRPC tunnel,
// evaluates RBAC policy, injects caller context headers if allowed, and either
// forwards the modified request to the application or returns HTTP 403.
package gateway

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/inspect"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/logging"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/rbac"
)

// Interceptor handles RBAC evaluation for a single tunneled request.
type Interceptor struct {
	engine *rbac.Engine
	logger *logging.AccessLogger
}

// NewInterceptor creates a gateway interceptor.
func NewInterceptor(engine *rbac.Engine, logger *logging.AccessLogger) *Interceptor {
	return &Interceptor{
		engine: engine,
		logger: logger,
	}
}

// Result of intercepting a request.
type InterceptResult struct {
	// Allowed indicates whether the request should be forwarded.
	Allowed bool
	// DenyResponse is the HTTP 403 response to send back through the tunnel if denied.
	DenyResponse []byte
	// RequestID is the unique ID assigned to this request for correlation.
	RequestID string
}

// Process evaluates a parsed request and injects authenticated headers if allowed.
// A nil request records a fail-closed HTTP parsing denial.
// callerSpiffeID is extracted from the mTLS peer certificate.
func (i *Interceptor) Process(callerSpiffeID string, req *http.Request) InterceptResult {
	start := time.Now()
	requestID := fmt.Sprintf("req-%s", uuid.New().String()[:8])

	// Build caller identity (used for header injection and audit logging).
	callerID := inspect.CallerIdentity{
		SpiffeID:    callerSpiffeID,
		TrustDomain: extractTrustDomain(callerSpiffeID),
		RequestID:   requestID,
	}
	if cp := i.engine.FindCallerPolicy(callerSpiffeID); cp != nil {
		callerID.EntraAgentID = cp.EntraAgentID
	}

	if req == nil {
		// If we can't parse HTTP, we can't evaluate RBAC. Deny.
		i.logEntryWithJWT(callerID, "UNKNOWN", "UNKNOWN", "deny", rbac.Decision{
			Action: rbac.ActionDeny, Reason: "parse_error", EnforcementLayer: rbac.LayerRBAC,
		}, requestID, start)
		return InterceptResult{
			Allowed:      false,
			DenyResponse: inspect.BuildDenyResponse(requestID, callerSpiffeID, "UNKNOWN", "UNKNOWN"),
			RequestID:    requestID,
		}
	}

	// Extract Bearer token from Authorization header for Layer 3 (OAuth/JWT).
	// Parse case-insensitively and trim whitespace per RFC 6750.
	bearerToken := ""
	authorization := req.Header.Get("Authorization")
	if len(authorization) > 7 && strings.EqualFold(authorization[:7], "Bearer ") {
		bearerToken = strings.TrimSpace(authorization[7:])
	}

	log.Printf("[Gateway] Request: %s %s from %s (jwt_present: %v)", req.Method, req.URL.Path, callerSpiffeID, bearerToken != "")

	// Step 2: RBAC + JWT evaluation (Layers 2 and 3).
	decision := i.engine.Evaluate(callerSpiffeID, req.Method, req.URL.Path, bearerToken)

	if decision.Action == rbac.ActionDeny {
		log.Printf("[Gateway] ❌ DENIED: %s %s from %s (reason: %s, layer: %s)",
			req.Method, req.URL.Path, callerSpiffeID, decision.Reason, decision.EnforcementLayer)
		i.logEntryWithJWT(callerID, req.Method, req.URL.Path, "deny", decision, requestID, start)

		denyResp := i.buildDenyResponseFromDecision(decision, requestID, callerSpiffeID, req.Method, req.URL.Path)
		return InterceptResult{
			Allowed:      false,
			DenyResponse: denyResp,
			RequestID:    requestID,
		}
	}

	// Step 3: Inject caller context headers (SPIFFE + Entra).
	inspect.InjectHeaders(req, callerID)
	log.Printf("[Gateway] ✓ ALLOWED: %s %s from %s (reason: %s, layer: %s)",
		req.Method, req.URL.Path, callerSpiffeID, decision.Reason, decision.EnforcementLayer)
	i.logEntryWithJWT(callerID, req.Method, req.URL.Path, "allow", decision, requestID, start)

	return InterceptResult{
		Allowed:   true,
		RequestID: requestID,
	}
}

func (i *Interceptor) logEntryWithJWT(id inspect.CallerIdentity, method, path, decisionStr string, decision rbac.Decision, requestID string, start time.Time) {
	i.logger.Log(logging.AccessEntry{
		CallerSpiffeID:     id.SpiffeID,
		EntraAgentID:       id.EntraAgentID,
		Method:             method,
		Path:               path,
		Decision:           decisionStr,
		Reason:             decision.Reason,
		EnforcementLayer:   decision.EnforcementLayer,
		LatencyMs:          time.Since(start).Milliseconds(),
		RequestID:          requestID,
		JWTPresent:         decision.JWTPresent,
		JWTValid:           decision.JWTValid,
		JWTAudience:        decision.JWTAudience,
		JWTRoles:           decision.JWTRoles,
		JWTValidationError: decision.JWTError,
		CustomClaims:       decision.CustomClaims,
	})
}

// buildDenyResponseFromDecision constructs an appropriate HTTP error response
// based on the enforcement layer and status code in the decision.
func (i *Interceptor) buildDenyResponseFromDecision(decision rbac.Decision, requestID, callerSpiffeID, method, path string) []byte {
	// For standard RBAC denials, use the existing response format.
	if decision.EnforcementLayer == rbac.LayerRBAC {
		return inspect.BuildDenyResponse(requestID, callerSpiffeID, method, path)
	}

	// OAuth-layer denials get richer error details.
	statusCode := decision.StatusCode
	if statusCode == 0 {
		statusCode = 403
	}

	errorBody := map[string]interface{}{
		"error":      decision.Reason,
		"layer":      decision.EnforcementLayer,
		"request_id": requestID,
		"caller":     callerSpiffeID,
	}
	if decision.JWTError != "" {
		errorBody["detail"] = decision.JWTError
	}
	if decision.MatchedRule != nil && len(decision.MatchedRule.RequiredRoles) > 0 {
		errorBody["required_roles"] = decision.MatchedRule.RequiredRoles
	}
	if len(decision.JWTRoles) > 0 {
		errorBody["actual_roles"] = decision.JWTRoles
	}

	body, _ := json.Marshal(errorBody)

	statusText := "Forbidden"
	if statusCode == 401 {
		statusText = "Unauthorized"
	}

	return inspect.BuildDenyResponseWithCode(statusCode, statusText, requestID, body)
}

func extractTrustDomain(spiffeID string) string {
	// spiffe://aim.microsoft.com/ests/bp/<blueprint>/aid/<agent> -> aim.microsoft.com
	trimmed := strings.TrimPrefix(spiffeID, "spiffe://")
	if idx := strings.Index(trimmed, "/"); idx > 0 {
		return trimmed[:idx]
	}
	return trimmed
}
