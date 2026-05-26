// Package gateway integrates the RBAC engine, HTTP inspection, structured logging,
// and management API into the existing tunnel ingress proxy.
//
// It intercepts the first data payload in the gRPC tunnel, parses the HTTP request,
// evaluates RBAC policy, injects caller context headers if allowed, and either
// forwards the modified request to the application or returns HTTP 403.
package gateway

import (
	"encoding/json"
	"fmt"
	"log"
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
	// ModifiedPayload is the payload to forward (with injected headers) if allowed.
	ModifiedPayload []byte
	// DenyResponse is the HTTP 403 response to send back through the tunnel if denied.
	DenyResponse []byte
	// RequestID is the unique ID assigned to this request for correlation.
	RequestID string
	// RemainingBodyBytes is the number of request body bytes still expected after
	// this payload. When > 0, the tunnel server should allow additional DATA payloads
	// until the full body is received, then activate anti-smuggling protection.
	// A value of -1 means Content-Length was not specified (should not happen for
	// well-formed PUT/POST from httpx, but if so we conservatively allow body data
	// up to a maximum limit).
	RemainingBodyBytes int64
}

// Process evaluates the first data payload from the tunnel.
// callerSpiffeID is extracted from the mTLS peer certificate.
func (i *Interceptor) Process(callerSpiffeID string, payload []byte) InterceptResult {
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

	// Step 1: Parse HTTP request from tunnel payload.
	reqInfo, err := inspect.ParseHTTPRequest(payload)
	if err != nil {
		// If we can't parse HTTP, we can't evaluate RBAC. Deny.
		log.Printf("[Gateway] Failed to parse HTTP from tunnel payload: %v", err)
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
	if len(reqInfo.Authorization) > 7 && strings.EqualFold(reqInfo.Authorization[:7], "Bearer ") {
		bearerToken = strings.TrimSpace(reqInfo.Authorization[7:])
	}

	log.Printf("[Gateway] Request: %s %s from %s (jwt_present: %v)", reqInfo.Method, reqInfo.Path, callerSpiffeID, bearerToken != "")

	// Step 2: RBAC + JWT evaluation (Layers 2 and 3).
	decision := i.engine.Evaluate(callerSpiffeID, reqInfo.Method, reqInfo.Path, bearerToken)

	if decision.Action == rbac.ActionDeny {
		log.Printf("[Gateway] ❌ DENIED: %s %s from %s (reason: %s, layer: %s)",
			reqInfo.Method, reqInfo.Path, callerSpiffeID, decision.Reason, decision.EnforcementLayer)
		i.logEntryWithJWT(callerID, reqInfo.Method, reqInfo.Path, "deny", decision, requestID, start)

		denyResp := i.buildDenyResponseFromDecision(decision, requestID, callerSpiffeID, reqInfo.Method, reqInfo.Path)
		return InterceptResult{
			Allowed:      false,
			DenyResponse: denyResp,
			RequestID:    requestID,
		}
	}

	// Step 3: Inject caller context headers (SPIFFE + Entra).
	modified, err := inspect.InjectHeaders(payload, callerID)
	if err != nil {
		// Header injection failed — deny the request rather than forwarding with
		// potentially spoofable caller-identity headers intact.
		log.Printf("[Gateway] Error: header injection failed, denying request: %v", err)
		denyDecision := decision
		denyDecision.Action = rbac.ActionDeny
		denyDecision.Reason = "header_injection_failed"
		// Keep original EnforcementLayer — this denial is distinguished via
		// Reason rather than being misattributed to RBAC.
		i.logEntryWithJWT(callerID, reqInfo.Method, reqInfo.Path, "deny", denyDecision, requestID, start)
		return InterceptResult{
			Allowed:      false,
			DenyResponse: inspect.BuildDenyResponse(requestID, callerSpiffeID, reqInfo.Method, reqInfo.Path),
			RequestID:    requestID,
		}
	}

	// Step 5: Calculate remaining body bytes for anti-smuggling.
	// The first payload may contain part of the body. We need to tell the tunnel
	// server how many more bytes to expect before activating anti-smuggling.
	var remainingBody int64
	if reqInfo.ContentLength > 0 {
		bodyInFirstPayload := int64(len(payload) - reqInfo.HeaderEndPos)
		if bodyInFirstPayload < 0 {
			bodyInFirstPayload = 0
		}
		remainingBody = reqInfo.ContentLength - bodyInFirstPayload
		if remainingBody < 0 {
			remainingBody = 0
		}
	} else if reqInfo.ContentLength == -1 {
		// No Content-Length header. Conservatively allow up to 1MB of body.
		remainingBody = 1 << 20
	}
	// ContentLength == 0 means no body expected — remainingBody stays 0.

	log.Printf("[Gateway] ✓ ALLOWED: %s %s from %s (reason: %s, layer: %s, remaining_body: %d)",
		reqInfo.Method, reqInfo.Path, callerSpiffeID, decision.Reason, decision.EnforcementLayer, remainingBody)
	i.logEntryWithJWT(callerID, reqInfo.Method, reqInfo.Path, "allow", decision, requestID, start)

	return InterceptResult{
		Allowed:            true,
		ModifiedPayload:    modified,
		RequestID:          requestID,
		RemainingBodyBytes: remainingBody,
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
