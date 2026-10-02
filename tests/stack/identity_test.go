package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestIdentityFixtureOutboundContainment(t *testing.T) {
	previous := http.DefaultTransport
	fixture, err := newIdentityFixture()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		fixture.Close()
		if http.DefaultTransport != previous {
			t.Error("fixture did not restore the original default transport")
		}
	})
	target, err := url.Parse(fixture.server.URL)
	if err != nil || net.ParseIP(target.Hostname()) == nil || !net.ParseIP(target.Hostname()).IsLoopback() {
		t.Fatal("identity fixture must bind to numeric loopback")
	}
	if fixture.transport.Proxy != nil {
		t.Fatal("identity fixture must not use an environment proxy")
	}
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:8080")
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:8080")
	t.Setenv("ALL_PROXY", "http://proxy.invalid:8080")
	t.Setenv("NO_PROXY", "")

	var dials atomic.Int64
	// Observe the real dial address, but never let a regression contact another host.
	fixture.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if address != target.Host {
			t.Errorf("outbound destination escaped the fixture: %q", address)
			return nil, fmt.Errorf("non-fixture dial rejected")
		}
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
	}

	for _, tc := range []struct {
		name, address string
		status        int
	}{
		{"oidc", "https://login.microsoftonline.com/stack-tenant/v2.0/.well-known/openid-configuration", 200},
		{"jwks", "https://login.microsoftonline.com/stack-jwks", 200},
		{"graph", "https://graph.microsoft.com/beta/identity/conditionalAccess/policies", 200},
		{"query_cannot_select_destination", "https://login.microsoftonline.com/stack-jwks?next=https://outside.invalid", 200},
		{"path_cannot_select_destination", "https://graph.microsoft.com//outside.invalid/path", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tc.address, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Close = true
			before := dials.Load()
			resp, err := http.DefaultTransport.RoundTrip(req)
			if err != nil {
				t.Fatal("fixture HTTP exchange failed:", err)
			}
			defer resp.Body.Close()
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.status || dials.Load() != before+1 {
				t.Fatal("request did not reach the expected loopback fixture handler")
			}
			if req.URL.String() != tc.address {
				t.Fatal("fixture transport mutated the caller's URL")
			}
		})
	}

	for _, address := range []string{
		"http://login.microsoftonline.com/stack-jwks",
		"http://graph.microsoft.com/beta/identity/conditionalAccess/policies",
		"https://outside.invalid/stack-jwks",
		"https://login.microsoftonline.com.outside.invalid/stack-jwks",
		"https://graph.microsoft.com.outside.invalid/stack-jwks",
		"https://graph.microsoft.com@outside.invalid/stack-jwks",
		"https://login.microsoftonline.com:443/stack-jwks",
		"https://graph.microsoft.com./stack-jwks",
		fixture.server.URL + "/stack-jwks",
	} {
		t.Run("reject_"+address, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, address, nil)
			if err != nil {
				t.Fatal(err)
			}
			before := dials.Load()
			resp, err := http.DefaultTransport.RoundTrip(req)
			if resp != nil {
				resp.Body.Close()
				t.Error("non-allowlisted request received a response")
			}
			if err == nil || dials.Load() != before {
				t.Fatal("non-allowlisted request was not blocked before dialing")
			}
		})
	}
}
