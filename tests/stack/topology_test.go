package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

func TestConnectedProductionClientAndServer(t *testing.T) {
	var dispatch atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Spiffe-Caller-Id") != callerID {
			t.Error("backend did not receive certificate-derived caller identity")
		}
		dispatch.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer backend.Close()
	stack, err := newTopology(backend.URL)
	if err != nil {
		t.Fatal("connected fixture startup failed:", err)
	}
	defer stack.Close()
	client := &http.Client{Timeout: 9 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()

	for _, tc := range []struct {
		name, method, path, layer string
		status                    int
		count                     int64
	}{
		{"allowed", "GET", "/budget/read", "oauth", 200, 1},
		{"rbac_deny", "POST", "/budget/submit", "rbac", 403, 0},
		{"jwt_missing", "GET", "/budget/read", "oauth", 401, 0},
		{"jwt_expired", "GET", "/budget/read", "oauth", 401, 0},
		{"jwt_wrong_audience", "GET", "/budget/read", "oauth", 401, 0},
		{"jwt_wrong_signature", "GET", "/budget/read", "oauth", 401, 0},
		{"ca_disabled", "GET", "/budget/read", "conditional_access", 403, 0},
		{"ca_tag_mismatch", "GET", "/budget/read", "conditional_access", 403, 0},
		{"ca_high_risk", "GET", "/budget/read", "conditional_access", 403, 0},
		{"allowed", "GET", "/budget/read", "oauth", 200, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dispatch.Store(0)
			if err := stack.setScenario(tc.name); err != nil {
				t.Fatal("scenario reset failed:", err)
			}
			req, _ := http.NewRequest(tc.method, stack.ready.EgressURL+tc.path, nil)
			req.Close = true
			token := stack.token()
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal("real production client/server HTTP exchange failed")
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			evidence := stack.evidence()
			if resp.StatusCode != tc.status || dispatch.Load() != tc.count {
				t.Fatalf("status=%d dispatch=%d; want status=%d dispatch=%d",
					resp.StatusCode, dispatch.Load(), tc.status, tc.count)
			}
			if len(evidence.Audit) != 1 || evidence.Audit[0].EnforcementLayer != tc.layer {
				t.Fatal("missing or wrong production gateway audit entry")
			}
			if tc.status == 200 && (!evidence.Audit[0].JWTValid || evidence.Audit[0].Decision != "allow") {
				t.Fatal("healthy control did not validate signed JWT")
			}
			if tc.status != 200 && evidence.Audit[0].Decision != "deny" {
				t.Fatal("negative HTTP outcome has no authorization-denial audit")
			}
		})
	}

	t.Run("management_mutation_drives_real_risk_engine", func(t *testing.T) {
		if err := stack.setScenario("allowed"); err != nil {
			t.Fatal(err)
		}
		dispatch.Store(0)
		req, _ := http.NewRequest(http.MethodPut, stack.ready.ManagementURL+"/admin/agent-risk",
			strings.NewReader(`{"spiffe_id":"`+callerID+`","risk_level":"high"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal("real management API unreachable")
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("production risk update status=%d", resp.StatusCode)
		}
		req, _ = http.NewRequest(http.MethodGet, stack.ready.EgressURL+"/budget/read", nil)
		req.Close = true
		req.Header.Set("Authorization", "Bearer "+stack.token())
		resp, err = client.Do(req)
		if err != nil {
			t.Fatal("post-mutation tunneled request failed")
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 403 || dispatch.Load() != 0 {
			t.Fatal("management update did not reach actual enforcement engine")
		}
		for _, prefix := range []string{"/admin", "/mgmt", ""} {
			resp, err = client.Get(stack.ready.ManagementURL + prefix + "/policy")
			if err != nil {
				t.Fatal("management prefix adapter failed")
			}
			var policy map[string]any
			err = json.NewDecoder(resp.Body).Decode(&policy)
			_ = resp.Body.Close()
			if err != nil || resp.StatusCode != 200 || policy["trust_domain"] != "stack.test" {
				t.Fatal("management prefix did not forward actual production policy")
			}
		}
		req, _ = http.NewRequest(http.MethodPut, stack.ready.ManagementURL+"/admin/agent-risk",
			strings.NewReader(`{"spiffe_id":"`+callerID+`","risk_level":"low"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err = client.Do(req)
		if err != nil {
			t.Fatal("real low-risk restoration failed")
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("production low-risk restoration status=%d", resp.StatusCode)
		}
		req, _ = http.NewRequest(http.MethodGet, stack.ready.EgressURL+"/budget/read", nil)
		req.Close = true
		req.Header.Set("Authorization", "Bearer "+stack.token())
		resp, err = client.Do(req)
		if err != nil {
			t.Fatal("post-restoration tunneled request failed")
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || dispatch.Load() != 1 {
			t.Fatal("low-risk restoration did not recover actual backend dispatch")
		}
		audit := stack.evidence().Audit
		if len(audit) != 2 || audit[0].Decision != "allow" || audit[1].Decision != "deny" ||
			audit[0].RequestID == "" || audit[1].RequestID == "" || audit[0].RequestID == audit[1].RequestID {
			t.Fatal("risk roundtrip did not preserve distinct production request audit IDs")
		}
	})

	t.Run("mtls_denial_has_transport_evidence_and_recovers", func(t *testing.T) {
		dispatch.Store(0)
		if err := stack.setScenario("mtls_denied"); err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodGet, stack.ready.EgressURL+"/budget/read", nil)
		req.Close = true
		req.Header.Set("Authorization", "Bearer "+stack.token())
		resp, err := client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		evidence := stack.evidence()
		if err == nil || dispatch.Load() != 0 || evidence.MTLSRejections == 0 {
			t.Fatal("mTLS rejection lacks production TLS authorizer evidence")
		}
		if len(evidence.Audit) != 0 {
			t.Fatal("transport rejection must not masquerade as HTTP gateway audit")
		}
		if err := stack.setScenario("allowed"); err != nil {
			t.Fatal("allowed scenario failed after transport reset")
		}
		if stack.evidence().MTLSRejections != 0 || len(stack.evidence().Audit) != 0 {
			t.Fatal("scenario evidence leaked across resets")
		}
	})

	t.Run("control_rejects_invalid_scenarios_without_state_changes", func(t *testing.T) {
		for _, data := range []string{
			`{}`, `{"name":"unknown"}`, `{"name":12}`, `{"name":"allowed","extra":true}`,
			`{"name":"allowed"} {}`, `{"name":"allowed","name":"ca_disabled"}`, `null`,
		} {
			before := stack.evidence().Scenario
			resp, err := client.Post(stack.ready.ControlURL+"/scenario", "application/json", strings.NewReader(data))
			if err != nil {
				t.Fatal("control request failed")
			}
			_ = resp.Body.Close()
			if resp.StatusCode != 400 || stack.evidence().Scenario != before {
				t.Fatal("invalid scenario modified fixture or was accepted")
			}
		}
		resp, err := client.Post(stack.ready.ControlURL+"/scenario", "application/json",
			strings.NewReader(`{"name":"jwt_missing"}`))
		if err != nil {
			t.Fatal("valid control request failed")
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || stack.token() != "" {
			t.Fatal("valid control request did not change fixture token boundary")
		}
		resp, err = client.Get(stack.ready.ControlURL + "/token")
		if err != nil {
			t.Fatal("token acquisition boundary failed")
		}
		defer resp.Body.Close()
		var token map[string]string
		if json.NewDecoder(resp.Body).Decode(&token) != nil || len(token) != 1 || token["access_token"] != "" {
			t.Fatal("token acquisition schema mismatch")
		}
	})

	t.Run("missing_governance_inputs_are_real_and_cold", func(t *testing.T) {
		if err := stack.setScenario("ca_policy_outage"); err != nil {
			t.Fatal(err)
		}
		status := stack.current.cache.Status()
		if status["fetch_count"].(int) != 0 || status["last_error"] == nil {
			t.Fatal("policy outage reused a warm cache or did not reach production Graph client")
		}
		if err := stack.setScenario("ca_missing_risk"); err != nil {
			t.Fatal(err)
		}
		if stack.current.risk.Count() != 0 {
			t.Fatal("missing risk fixture manufactured a safe risk entry")
		}
		if err := stack.setScenario("ca_graph_tag_absent"); err != nil {
			t.Fatal(err)
		}
		if _, ok := stack.current.tags.GetTag(callerID); ok {
			t.Fatal("missing Graph tag fixture contains an entry")
		}
	})

	t.Run("evidence_excludes_raw_jwt_errors_and_tokens", func(t *testing.T) {
		if err := stack.setScenario("jwt_wrong_signature"); err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodGet, stack.ready.EgressURL+"/budget/read", nil)
		req.Close = true
		token := stack.token()
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal("signed denial request failed")
		}
		_ = resp.Body.Close()
		data, err := json.Marshal(stack.evidence())
		if err != nil || bytes.Contains(data, []byte(token)) || bytes.Contains(data, []byte("jwt_validation_error")) {
			t.Fatal("evidence contains token or raw validation error")
		}
		var value map[string]json.RawMessage
		if json.Unmarshal(data, &value) != nil || len(value) != 3 {
			t.Fatal("evidence top-level schema is not closed")
		}
	})
}

func TestRejectNonLoopbackBackend(t *testing.T) {
	for _, value := range []string{"http://example.org:80", "http://localhost:8000",
		"http://127.0.0.1", "http://127.0.0.1:0", "https://127.0.0.1:80",
		"http://user:pass@127.0.0.1:80", "http://127.0.0.1:80/path"} {
		if _, err := backendAddress(value); err == nil {
			t.Fatal("unsafe backend accepted")
		}
	}
}
