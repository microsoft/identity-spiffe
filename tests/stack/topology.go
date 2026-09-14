package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/ca"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/gateway"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/logging"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/mgmt"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/mtls"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/rbac"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/tunnel"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"gopkg.in/yaml.v3"
)

type readiness struct {
	EgressURL      string `json:"egress_url"`
	ManagementURL  string `json:"management_url"`
	ControlURL     string `json:"control_url"`
	CallerSpiffeID string `json:"caller_spiffe_id"`
	Audience       string `json:"audience"`
}

type evidence struct {
	Scenario       string                `json:"scenario"`
	Audit          []logging.AccessEntry `json:"audit"`
	MTLSRejections int64                 `json:"mtls_rejections"`
}

type scenario struct {
	name      string
	token     string
	logger    *logging.AccessLogger
	risk      *rbac.RiskStore
	tags      *rbac.TagStore
	cache     *ca.PolicyCache
	ingress   *tunnel.Server
	listener  net.Listener
	clientTLS *tls.Config
	mgmt      *mgmt.Server
	mgmtURL   string
	rejected  atomic.Int64
	serveDone chan error
}

func (s *scenario) Close() {
	if s.mgmt != nil {
		s.mgmt.Stop()
	}
	if s.ingress != nil {
		s.ingress.Stop()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.cache != nil {
		s.cache.Stop()
	}
}

type topology struct {
	mu          sync.RWMutex
	current     *scenario
	identity    *identityFixture
	backendAddr string
	ready       readiness
	egress      net.Listener
	httpServers []*http.Server
	transport   *http.Transport
	connections sync.WaitGroup
	sequence    atomic.Int64
	closed      bool
}

func backendAddress(value string) (string, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("backend must be numeric loopback HTTP")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || u.Host != "127.0.0.1:"+strconv.Itoa(port) {
		return "", fmt.Errorf("backend must have an explicit valid port")
	}
	return u.Host, nil
}

func newTopology(backend string) (*topology, error) {
	addr, err := backendAddress(backend)
	if err != nil {
		return nil, err
	}
	t := &topology{backendAddr: addr, transport: &http.Transport{
		Proxy: nil, ResponseHeaderTimeout: 5 * time.Second}}
	t.identity, err = newIdentityFixture()
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*topology, error) { t.Close(); return nil, err }
	if err := t.setScenario("allowed"); err != nil {
		return fail(err)
	}
	t.egress, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fail(err)
	}
	t.ready = readiness{EgressURL: "http://" + t.egress.Addr().String(), CallerSpiffeID: callerID, Audience: audience}
	t.ready.ControlURL, err = t.serveHTTP(http.HandlerFunc(t.control))
	if err != nil {
		return fail(err)
	}
	t.ready.ManagementURL, err = t.serveHTTP(http.HandlerFunc(t.management))
	if err != nil {
		return fail(err)
	}
	go t.accept()
	return t, nil
}

func (t *topology) serveHTTP(handler http.Handler) (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 5 * time.Second}
	t.httpServers = append(t.httpServers, server)
	go func() { _ = server.Serve(listener) }()
	return "http://" + listener.Addr().String(), nil
}

func (t *topology) accept() {
	for {
		conn, err := t.egress.Accept()
		if err != nil {
			return
		}
		t.mu.RLock()
		if t.closed {
			t.mu.RUnlock()
			_ = conn.Close()
			return
		}
		s := t.current
		t.connections.Add(1)
		go func() {
			defer t.connections.Done()
			defer t.mu.RUnlock()
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
			client, err := tunnel.NewClient(s.listener.Addr().String(), s.clientTLS)
			if err != nil {
				return
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			_ = client.ForwardConnection(ctx, conn, fmt.Sprintf("stack-%d", t.sequence.Add(1)))
		}()
	}
}

func (t *topology) Close() {
	for _, server := range t.httpServers {
		_ = server.Close()
	}
	if t.egress != nil {
		_ = t.egress.Close()
	}
	t.mu.Lock()
	t.closed = true
	if t.current != nil {
		t.current.Close()
	}
	t.mu.Unlock()
	t.connections.Wait()
	t.transport.CloseIdleConnections()
	if t.identity != nil {
		t.identity.Close()
	}
}

func validScenario(name string) bool {
	switch name {
	case "allowed", "rbac_deny", "jwt_missing", "jwt_expired", "jwt_wrong_audience",
		"jwt_wrong_signature", "jwt_no_expiry", "ca_disabled", "ca_tag_mismatch",
		"ca_high_risk", "ca_missing_risk", "ca_policy_outage", "ca_graph_tag_absent", "mtls_denied":
		return true
	}
	return false
}

func basePolicy() rbac.Policy {
	return rbac.Policy{
		Version: "3.0", TrustDomain: "stack.test", DefaultAction: rbac.ActionDeny,
		AdminGovernance: rbac.AdminGovernance{Enabled: true, TargetAgentTag: "Finance", RiskEnforcement: "data_plane"},
		Policies: []rbac.CallerPolicy{{
			Name: "budget-report", SpiffeID: callerID, EntraAgentID: "stack-caller",
			CA: rbac.CAPolicy{AgentState: "enabled", AgentTag: "Finance"},
			Rules: []rbac.Rule{
				{Path: "/budget/submit", Methods: []string{"*"}, Action: rbac.ActionDeny},
				{Path: "/budget/read", Methods: []string{"GET"}, Action: rbac.ActionAllow,
					RequireJWT: true, RequiredRoles: []string{"Budget.Read"}},
			},
		}},
	}
}

func (t *topology) setScenario(name string) error {
	if !validScenario(name) {
		return fmt.Errorf("unknown scenario")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s, err := t.makeScenario(name)
	if err != nil {
		return err
	}
	old := t.current
	t.current = s
	if old != nil {
		old.Close()
	}
	return nil
}

func (t *topology) makeScenario(name string) (*scenario, error) {
	s := &scenario{name: name, logger: logging.NewAccessLogger(128),
		risk: rbac.NewRiskStore(), tags: rbac.NewTagStore()}
	fail := func(err error) (*scenario, error) { s.Close(); return nil, err }
	var err error
	s.token, err = t.identity.signedToken(name)
	if err != nil {
		return fail(err)
	}
	validator, err := t.identity.primedValidator()
	if err != nil {
		return fail(err)
	}
	p := basePolicy()
	if name == "ca_disabled" {
		p.Policies[0].CA.AgentState = "disabled"
	}
	if name != "ca_missing_risk" {
		level := rbac.RiskLow
		if name == "ca_high_risk" || name == "ca_policy_outage" {
			level = rbac.RiskHigh
		}
		s.risk.SetRisk(callerID, level)
	}
	if name != "ca_graph_tag_absent" {
		tag := "Finance"
		if name == "ca_tag_mismatch" {
			tag = "Engineering"
		}
		s.tags.SetTag(callerID, tag)
	}
	t.identity.mu.Lock()
	t.identity.outage = name == "ca_policy_outage"
	t.identity.mu.Unlock()
	s.cache = ca.NewPolicyCache(ca.NewGraphClient("stack-tenant", "synthetic-client", "synthetic-not-a-secret"), time.Hour)
	s.cache.Start()
	cacheStatus := s.cache.Status()
	if name == "ca_policy_outage" {
		if cacheStatus["fetch_count"].(int) != 0 || cacheStatus["last_error"] == nil {
			return fail(fmt.Errorf("policy outage did not reach fresh production Graph cache"))
		}
	} else if cacheStatus["fetch_count"].(int) != 1 || len(s.cache.GetBlockedRiskLevels()) != 1 {
		return fail(fmt.Errorf("production Graph cache was not primed"))
	}
	store := rbac.NewPolicyStore()
	data, err := yaml.Marshal(p)
	if err != nil {
		return fail(err)
	}
	if err := store.LoadFromBytes(data); err != nil {
		return fail(err)
	}
	auth := mtls.NewDynamicAuthorizer([]spiffeid.ID{spiffeid.RequireFromString(callerID)}, func(id string) {
		s.logger.LogMTLSRejection(id)
		s.rejected.Add(1)
	})
	serverTLS, clientTLS, err := tlsPair(auth)
	if err != nil {
		return fail(err)
	}
	s.clientTLS = clientTLS
	s.listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fail(err)
	}
	s.ingress = tunnel.NewServer(t.backendAddr, serverTLS, serverID)
	s.ingress.SetDynamicAuth(auth)
	engine := rbac.NewEngine(store, validator, s.risk, s.tags, rbac.WithCAPolicyCache(s.cache))
	s.ingress.SetInterceptor(gateway.NewInterceptor(engine, s.logger))
	s.serveDone = make(chan error, 1)
	go func() { s.serveDone <- s.ingress.Serve(s.listener) }()
	prime, err := tunnel.NewClient(s.listener.Addr().String(), s.clientTLS)
	if err != nil {
		return fail(fmt.Errorf("healthy production tunnel health check failed"))
	}
	_ = prime.Close()
	if name == "mtls_denied" {
		auth.Update(nil)
	}
	// The production management constructor accepts a port rather than a
	// listener. Reserve an ephemeral port and retry only bind collisions.
	for attempt := 0; attempt < 5; attempt++ {
		reservation, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fail(err)
		}
		port := reservation.Addr().(*net.TCPAddr).Port
		_ = reservation.Close()
		server := mgmt.NewServer(port, store, s.logger, nil, auth, validator, s.risk, s.tags,
			mgmt.WithCAPolicyCache(s.cache))
		if err := server.Start(); err == nil {
			s.mgmt = server
			s.mgmtURL = fmt.Sprintf("http://127.0.0.1:%d", port)
			return s, nil
		}
	}
	return fail(fmt.Errorf("production management listener could not bind"))
}

func (t *topology) token() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.current.token
}

func (t *topology) evidence() evidence {
	t.mu.RLock()
	defer t.mu.RUnlock()
	entries := []logging.AccessEntry{}
	for _, entry := range t.current.logger.Recent(128, "", "") {
		if entry.EnforcementLayer == "mtls" {
			continue
		}
		entry.JWTValidationError = ""
		entry.CustomClaims = nil
		entries = append(entries, entry)
	}
	return evidence{Scenario: t.current.name, Audit: entries, MTLSRejections: t.current.rejected.Load()}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}

func decodeScenario(r *http.Request) (string, error) {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1025))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return "", fmt.Errorf("scenario must be an object")
	}
	var name string
	if !decoder.More() {
		return "", fmt.Errorf("scenario name required")
	}
	key, err := decoder.Token()
	if err != nil || key != "name" || decoder.Decode(&name) != nil || decoder.More() {
		return "", fmt.Errorf("scenario accepts only one string name")
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return "", fmt.Errorf("invalid scenario object")
	}
	if _, err := decoder.Token(); err != io.EOF || !validScenario(name) {
		return "", fmt.Errorf("invalid scenario name or trailing data")
	}
	return name, nil
}

func (t *topology) control(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/health":
		writeJSON(w, map[string]string{"status": "ready"})
	case r.Method == http.MethodGet && r.URL.Path == "/token":
		writeJSON(w, map[string]string{"access_token": t.token()})
	case r.Method == http.MethodGet && r.URL.Path == "/evidence":
		writeJSON(w, t.evidence())
	case r.Method == http.MethodPost && r.URL.Path == "/scenario":
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		name, err := decodeScenario(r)
		if err != nil {
			http.Error(w, "invalid scenario", http.StatusBadRequest)
			return
		}
		if err := t.setScenario(name); err != nil {
			http.Error(w, "fixture reset failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"scenario": name})
	default:
		http.NotFound(w, r)
	}
}

func (t *topology) management(w http.ResponseWriter, r *http.Request) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed {
		http.Error(w, "stack stopped", http.StatusServiceUnavailable)
		return
	}
	target, _ := url.Parse(t.current.mgmtURL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = t.transport
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "production management unavailable", http.StatusBadGateway)
	}
	copyReq := r.Clone(r.Context())
	copyURL := *r.URL
	for _, prefix := range []string{"/admin/", "/mgmt/"} {
		if strings.HasPrefix(copyURL.Path, prefix) {
			copyURL.Path = "/" + strings.TrimPrefix(copyURL.Path, prefix)
			break
		}
	}
	copyReq.URL = &copyURL
	proxy.ServeHTTP(w, copyReq)
}
