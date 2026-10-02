package ca

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const riskAgent = "11111111-1111-4111-8111-111111111111"

func TestRiskCacheFreshnessAndEveryRequest(t *testing.T) {
	calls := 0
	level := "low"
	fail := false
	client := NewGraphClient("fixture", "fixture", "fixture")
	client.token, client.expireAt = "fixture-token", time.Now().Add(time.Hour)
	client.httpClient.Transport = policyTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/beta/identityProtection/riskyAgents/"+riskAgent {
			t.Fatalf("unexpected risk route: %s", req.URL.Path)
		}
		calls++
		if fail {
			return nil, fmt.Errorf("fixture unavailable")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(
			fmt.Sprintf(`{"id":%q,"riskLevel":%q}`, riskAgent, level))), Header: http.Header{}}, nil
	})
	cache := NewRiskCache(client)
	now := time.Now()
	cache.now = func() time.Time { return now }
	check := func(ttl time.Duration, want string, wantError bool) {
		t.Helper()
		got, err := cache.GetRisk(riskAgent, ttl)
		if (err != nil) != wantError || got != want {
			t.Fatalf("risk=%q err=%v; wanted %q error=%v", got, err, want, wantError)
		}
	}
	check(90*time.Second, "low", false)
	level = "high"
	now = now.Add(89 * time.Second)
	check(90*time.Second, "low", false)
	if calls != 1 {
		t.Fatalf("fresh evidence was not cached: %d calls", calls)
	}
	now = now.Add(time.Second)
	check(90*time.Second, "high", false)
	check(0, "high", false)
	check(0, "high", false)
	if calls != 4 {
		t.Fatalf("expiry/zero TTL did not fetch: %d calls", calls)
	}
	fail = true
	check(0, "", true)
	check(90*time.Second, "", true)
}

func TestRiskCacheRejectsMissingAndInvalidEvidence(t *testing.T) {
	for _, body := range []string{
		`{}`, `{"id":"` + riskAgent + `"}`, `{"id":"` + riskAgent + `","riskLevel":null}`,
		`{"id":"` + riskAgent + `","riskLevel":"unknownFutureValue"}`,
		`{"id":"22222222-2222-4222-8222-222222222222","riskLevel":"low"}`,
		`{"id":"` + riskAgent + `","riskLevel":"high","riskState":"confirmedSafe"}`,
	} {
		t.Run(body, func(t *testing.T) {
			client := NewGraphClient("fixture", "fixture", "fixture")
			client.token, client.expireAt = "fixture-token", time.Now().Add(time.Hour)
			client.httpClient.Transport = policyTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
			})
			risk, err := NewRiskCache(client).GetRisk(riskAgent, 0)
			if strings.Contains(body, `"riskLevel":"high"`) {
				if err != nil || risk != "high" {
					t.Fatalf("confirmedSafe must not override a high rating: %q %v", risk, err)
				}
			} else if err == nil || risk != "" {
				t.Fatalf("invalid evidence accepted: %q %v", risk, err)
			}
		})
	}
	if _, err := NewRiskCache(nil).GetRisk(riskAgent, 0); err == nil {
		t.Fatal("missing credentials accepted")
	}
}
