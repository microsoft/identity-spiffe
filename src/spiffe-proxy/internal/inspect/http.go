// Package inspect provides HTTP request extraction and header injection
// for the SPIFFE sidecar gateway's L7 inspection pipeline.
package inspect

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// RequestInfo holds the parsed HTTP request metadata needed for RBAC evaluation.
type RequestInfo struct {
	Method        string
	Path          string
	Host          string
	ContentLength int64  // -1 if not specified
	HeaderEndPos  int    // byte offset where headers end (end of \r\n\r\n)
	Authorization string // Authorization header value (for Bearer token extraction)
}

// ParseHTTPRequest extracts method, path, host, and Content-Length from raw HTTP bytes.
// It parses only the request line and headers — the body is not consumed.
// Returns the parsed info and any error.
func ParseHTTPRequest(data []byte) (*RequestInfo, error) {
	reader := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, fmt.Errorf("parse HTTP request: %w", err)
	}
	defer req.Body.Close()

	// Find the end of headers (\r\n\r\n) to calculate how much body is in this payload.
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd >= 0 {
		headerEnd += 4 // skip past \r\n\r\n
	} else {
		headerEnd = len(data)
	}

	return &RequestInfo{
		Method:        req.Method,
		Path:          req.URL.Path,
		Host:          req.Host,
		ContentLength: req.ContentLength,
		HeaderEndPos:  headerEnd,
		Authorization: req.Header.Get("Authorization"),
	}, nil
}

// CallerIdentity holds the full identity chain for header injection.
type CallerIdentity struct {
	SpiffeID    string
	TrustDomain string
	RequestID   string
	EntraAgentID string // optional — from RBAC policy metadata
}

// InjectHeaders takes raw HTTP request bytes and injects caller identity
// headers after the request line. It strips any existing X-SPIFFE-* headers
// first to prevent spoofing, then adds the authenticated values.
//
// The function manually reconstructs the request rather than using req.Write()
// to avoid a Content-Length mismatch when the request body spans multiple
// tunnel messages. req.Write() reads from req.Body (only the partial body in
// this buffer) but the Content-Length header reflects the total body size.
//
// Headers injected:
//   - X-SPIFFE-Caller-ID: the authenticated caller's full SPIFFE ID
//   - X-SPIFFE-Trust-Domain: the trust domain from the SPIFFE ID
//   - X-SPIFFE-Entra-Agent-ID: the caller's Entra Agent ID (if known)
//   - X-Request-ID: unique request identifier for correlation
func InjectHeaders(data []byte, id CallerIdentity) ([]byte, error) {
	reader := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, fmt.Errorf("parse HTTP for header injection: %w", err)
	}
	defer req.Body.Close()

	// Strip existing identity-bearing X-SPIFFE-* headers and X-Request-ID
	// to prevent spoofing. The shared-secret X-Spiffe-Admin-Key header is
	// preserved — it is not an identity assertion but a control-plane
	// credential that admin-control-plane forwards to budget-backend's
	// /mgmt/* routes, and stripping it breaks the portal health probe and
	// every other ACP → backend management call.
	for key := range req.Header {
		if !strings.HasPrefix(key, "X-Spiffe-") {
			continue
		}
		if strings.EqualFold(key, "X-Spiffe-Admin-Key") {
			continue
		}
		req.Header.Del(key)
	}
	req.Header.Del("X-Request-ID")

	// Inject authenticated values.
	req.Header.Set("X-SPIFFE-Caller-ID", id.SpiffeID)
	req.Header.Set("X-SPIFFE-Trust-Domain", id.TrustDomain)
	req.Header.Set("X-Request-ID", id.RequestID)
	if id.EntraAgentID != "" {
		req.Header.Set("X-SPIFFE-Entra-Agent-ID", id.EntraAgentID)
	}

	// Find the end of headers in the original data to preserve body bytes as-is.
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	var bodyBytes []byte
	if headerEnd >= 0 {
		bodyBytes = data[headerEnd+4:]
	}

	// Remove headers we write explicitly to avoid duplicates (ReadRequest
	// may leave Host and Content-Length in req.Header on some Go versions).
	req.Header.Del("Host")
	req.Header.Del("Content-Length")

	// Manually reconstruct: request line + explicit headers + modified
	// headers + original body bytes. Preserves the original Content-Length
	// so the downstream app knows the total body size even when the body
	// spans multiple tunnel messages.
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s %s\r\n", req.Method, req.URL.RequestURI(), req.Proto)
	if req.Host != "" {
		fmt.Fprintf(&buf, "Host: %s\r\n", req.Host)
	}
	if req.ContentLength >= 0 {
		fmt.Fprintf(&buf, "Content-Length: %d\r\n", req.ContentLength)
	}
	req.Header.Write(&buf)
	buf.WriteString("\r\n")
	if len(bodyBytes) > 0 {
		buf.Write(bodyBytes)
	}
	return buf.Bytes(), nil
}

// BuildDenyResponse creates an HTTP 403 Forbidden response as raw bytes,
// suitable for sending back through the gRPC tunnel when RBAC denies a request.
// The callerID, method, and path parameters are retained in the signature for
// logging purposes in the caller but are intentionally excluded from the
// response body to prevent information disclosure.
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

// BuildDenyResponseWithCode creates an HTTP deny response with a custom status code
// and JSON body. Used for OAuth-layer denials (401/403) with richer error details.
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
