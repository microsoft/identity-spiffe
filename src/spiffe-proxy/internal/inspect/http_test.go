package inspect

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"
	"testing"
)

func TestInjectHeaders_StripsSpoofableSpiffeHeadersButPreservesAdminKey(t *testing.T) {
	raw := "GET /mgmt/health HTTP/1.1\r\n" +
		"Host: budget-backend:8000\r\n" +
		"X-SPIFFE-Caller-ID: spiffe://attacker.example/fake\r\n" +
		"X-SPIFFE-Trust-Domain: attacker.example\r\n" +
		"X-Spiffe-Admin-Key: shared-secret-123\r\n" +
		"X-Request-ID: spoofed-id\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"

	id := CallerIdentity{
		SpiffeID:    "spiffe://aim.microsoft.com/agents/admin",
		TrustDomain: "aim.microsoft.com",
		RequestID:   "real-req-id",
	}

	out, err := InjectHeaders([]byte(raw), id)
	if err != nil {
		t.Fatalf("InjectHeaders: %v", err)
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(out)))
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}

	if got := req.Header.Get("X-Spiffe-Admin-Key"); got != "shared-secret-123" {
		t.Errorf("X-Spiffe-Admin-Key must be preserved (control-plane shared secret), got %q", got)
	}
	if got := req.Header.Get("X-SPIFFE-Caller-ID"); got != id.SpiffeID {
		t.Errorf("X-SPIFFE-Caller-ID = %q, want %q (must be overwritten with authenticated value)", got, id.SpiffeID)
	}
	if got := req.Header.Get("X-SPIFFE-Trust-Domain"); got != id.TrustDomain {
		t.Errorf("X-SPIFFE-Trust-Domain = %q, want %q", got, id.TrustDomain)
	}
	if got := req.Header.Get("X-Request-ID"); got != id.RequestID {
		t.Errorf("X-Request-ID = %q, want %q", got, id.RequestID)
	}

	if strings.Count(string(out), "X-Spiffe-Admin-Key:") != 1 {
		t.Errorf("X-Spiffe-Admin-Key must appear exactly once in serialized output")
	}
}
