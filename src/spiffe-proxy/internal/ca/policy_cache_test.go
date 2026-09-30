package ca

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type policyTransport func(*http.Request) (*http.Response, error)

func (f policyTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPolicyCacheAvailabilityAndRefresh(t *testing.T) {
	for _, initial := range []string{
		`{"value":[]}`,
		`{"value":[{"state":"disabled","conditions":{"agentIdRiskLevels":["high"]},"grantControls":{"builtInControls":["block"]}}]}`,
		`{"value":[{"state":"enabled","conditions":{"agentIdRiskLevels":["high"]},"grantControls":{"builtInControls":["block"]}}]}`,
	} {
		t.Run(initial, func(t *testing.T) {
			body, status := initial, http.StatusOK
			var transportErr error
			client := NewGraphClient("fixture", "fixture", "synthetic-not-a-secret")
			client.token, client.expireAt = "synthetic-token", time.Now().Add(time.Hour)
			client.httpClient = &http.Client{Transport: policyTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != graphBeta+"/identity/conditionalAccess/policies" {
					t.Fatalf("unexpected request: %s", r.URL)
				}
				if transportErr != nil {
					return nil, transportErr
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})}
			cache := NewPolicyCache(client, time.Hour)
			if got := cache.Status()["ready"]; got != false {
				t.Errorf("new cache readiness = %v, want false", got)
			}
			for _, failure := range []string{"http", "timeout", "json", "missing_value", "null_value"} {
				setFailure := func() {
					status, body, transportErr = http.StatusOK, initial, nil
					switch failure {
					case "http":
						status = http.StatusServiceUnavailable
					case "timeout":
						transportErr = fmt.Errorf("fixture timeout")
					case "json":
						body = "{"
					case "missing_value":
						body = "{}"
					case "null_value":
						body = `{"value":null}`
					}
				}
				setFailure()
				cache.refresh()
				if got := cache.Status()["ready"]; got != false {
					t.Errorf("initial %s readiness = %v, want false", failure, got)
				}
				if cache.Status()["last_error"] == nil {
					t.Errorf("initial %s error not reported", failure)
				}
			}
			status, body, transportErr = http.StatusOK, initial, nil
			cache.refresh()
			if got := cache.Status()["ready"]; got != true {
				t.Fatalf("healthy policy readiness = %v, want true", got)
			}
			levels := cache.GetBlockedRiskLevels()
			wantCount := 0
			if strings.Contains(initial, `"state":"enabled"`) {
				wantCount = 1
			}
			if len(levels) != wantCount {
				t.Fatalf("blocked levels = %v, want count %d", levels, wantCount)
			}
			status = http.StatusServiceUnavailable
			cache.refresh()
			if cache.Status()["ready"] != true || cache.Status()["last_error"] == nil ||
				len(cache.GetBlockedRiskLevels()) != wantCount || cache.Status()["fetch_count"] != 1 {
				t.Fatalf("refresh outage must preserve observed policy: %v", cache.Status())
			}
			status, body = http.StatusOK, `{"value":[]}`
			cache.refresh()
			if cache.Status()["ready"] != true || cache.Status()["last_error"] != nil ||
				len(cache.GetBlockedRiskLevels()) != 0 || cache.Status()["fetch_count"] != 2 {
				t.Fatalf("healthy refresh must replace last-known-good policy: %v", cache.Status())
			}
		})
	}
}
