// Package inspect provides authenticated header injection and denial responses
// for the SPIFFE sidecar gateway's L7 inspection pipeline.
package inspect

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// CallerIdentity holds the full identity chain for header injection.
type CallerIdentity struct {
	SpiffeID     string
	TrustDomain  string
	RequestID    string
	EntraAgentID string
}

// InjectHeaders replaces spoofable identity headers with authenticated values.
func InjectHeaders(req *http.Request, id CallerIdentity) {
	// The admin key is a control-plane credential, not an identity assertion.
	// ACP forwards it to backend /mgmt/* routes.
	for key := range req.Header {
		if strings.HasPrefix(key, "X-Spiffe-") && !strings.EqualFold(key, "X-Spiffe-Admin-Key") {
			req.Header.Del(key)
		}
	}
	req.Header.Set("X-SPIFFE-Caller-ID", id.SpiffeID)
	req.Header.Set("X-SPIFFE-Trust-Domain", id.TrustDomain)
	req.Header.Set("X-Request-ID", id.RequestID)
	if id.EntraAgentID != "" {
		req.Header.Set("X-SPIFFE-Entra-Agent-ID", id.EntraAgentID)
	}
}

// BuildDenyResponse creates an HTTP 403 Forbidden response as raw bytes.
// Caller identity and route are deliberately excluded to avoid disclosure.
func BuildDenyResponse(requestID, callerID, method, path string) []byte {
	bodyMap := map[string]string{
		"error":      "forbidden",
		"request_id": requestID,
	}
	bodyBytes, err := json.Marshal(bodyMap)
	if err != nil {
		bodyBytes = []byte(`{"error":"forbidden"}`)
	}
	resp := fmt.Sprintf(
		"HTTP/1.1 403 Forbidden\r\n"+
			"Content-Type: application/json\r\n"+
			"Content-Length: %d\r\n"+
			"X-Request-ID: %s\r\n"+
			"X-Denied-By: spiffe-rbac-gateway\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"%s",
		len(bodyBytes), requestID, string(bodyBytes),
	)
	return []byte(resp)
}

// BuildDenyResponseWithCode creates an HTTP deny response with a custom status
// code and JSON body for OAuth-layer denials.
func BuildDenyResponseWithCode(statusCode int, statusText, requestID string, body []byte) []byte {
	resp := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\n"+
			"Content-Type: application/json\r\n"+
			"Content-Length: %d\r\n"+
			"X-Request-ID: %s\r\n"+
			"X-Denied-By: spiffe-rbac-gateway\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"%s",
		statusCode, statusText, len(body), requestID, string(body),
	)
	return []byte(resp)
}
