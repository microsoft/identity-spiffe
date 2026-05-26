package mgmt

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/project-aim/spiffe-proxy/internal/logging"
)

// dummyHandler returns 200 OK with body "ok" for any request.
func dummyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
}

func TestAuthMiddleware_NoKeySet(t *testing.T) {
	// When mgmtAPIKey is empty, all requests should pass through (fail-open).
	s := &Server{mgmtAPIKey: ""}
	handler := s.authMiddleware(dummyHandler())

	for _, path := range []string{"/health", "/policy", "/metrics", "/audit"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("path %s: expected 200 with no key set, got %d", path, rr.Code)
		}
	}
}

func TestAuthMiddleware_HealthBypassesAuth(t *testing.T) {
	// /health must be accessible even when a key is configured.
	s := &Server{mgmtAPIKey: "secret-key-123", apiKeyHash: sha256.Sum256([]byte("secret-key-123"))}
	handler := s.authMiddleware(dummyHandler())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	// No X-AIM-Admin-Key header set.
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("/health: expected 200, got %d", rr.Code)
	}
}

func TestAuthMiddleware_RejectsWithoutHeader(t *testing.T) {
	s := &Server{mgmtAPIKey: "secret-key-123", apiKeyHash: sha256.Sum256([]byte("secret-key-123"))}
	handler := s.authMiddleware(dummyHandler())

	for _, path := range []string{"/policy", "/metrics", "/audit", "/audit/stream", "/mtls-policy"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("path %s: expected 401 without header, got %d", path, rr.Code)
		}
	}
}

func TestAuthMiddleware_RejectsWrongKey(t *testing.T) {
	s := &Server{mgmtAPIKey: "secret-key-123", apiKeyHash: sha256.Sum256([]byte("secret-key-123"))}
	handler := s.authMiddleware(dummyHandler())

	req := httptest.NewRequest(http.MethodGet, "/policy", nil)
	req.Header.Set("X-AIM-Admin-Key", "wrong-key")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong key, got %d", rr.Code)
	}
}

func TestAuthMiddleware_AcceptsCorrectKey(t *testing.T) {
	s := &Server{mgmtAPIKey: "secret-key-123", apiKeyHash: sha256.Sum256([]byte("secret-key-123"))}
	handler := s.authMiddleware(dummyHandler())

	for _, path := range []string{"/policy", "/metrics", "/audit", "/audit/stream", "/mtls-policy"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-AIM-Admin-Key", "secret-key-123")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("path %s: expected 200 with correct key, got %d", path, rr.Code)
		}
	}
}

func TestAuthMiddleware_TimingSafeComparison(t *testing.T) {
	// Verify that a key that shares a prefix with the real key is still rejected.
	// This exercises the SHA-256 + subtle.ConstantTimeCompare path (not that we
	// can truly test timing here, but we can confirm it doesn't short-circuit on
	// prefix match).
	s := &Server{mgmtAPIKey: "secret-key-123", apiKeyHash: sha256.Sum256([]byte("secret-key-123"))}
	handler := s.authMiddleware(dummyHandler())

	req := httptest.NewRequest(http.MethodGet, "/policy", nil)
	req.Header.Set("X-AIM-Admin-Key", "secret-key-123-extra")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with prefix-extended key, got %d", rr.Code)
	}
}

func TestHandleAuditStream_EmitsEntries(t *testing.T) {
	logger := logging.NewAccessLogger(50)
	s := &Server{logger: logger, mgmtAPIKey: ""}
	srv := httptest.NewServer(s.authMiddleware(http.HandlerFunc(s.handleAuditStream)))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /audit/stream: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type: got %q, want text/event-stream", ct)
	}

	// Give the handler a moment to Subscribe, then publish an entry.
	time.Sleep(50 * time.Millisecond)
	logger.Log(logging.AccessEntry{CallerSpiffeID: "spiffe://t/x", Decision: "allow", Path: "/p"})

	// Give the server time to write the frame.
	time.Sleep(100 * time.Millisecond)

	buf := make([]byte, 4096)
	var body string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			body += string(buf[:n])
			if strings.Contains(body, "data: ") {
				break
			}
		}
		if err != nil {
			break
		}
	}
	if !strings.Contains(body, "data: ") {
		t.Errorf("expected SSE data frame, got %q", body)
	}
	if !strings.Contains(body, "spiffe://t/x") {
		t.Errorf("expected caller id in payload, got %q", body)
	}
}
