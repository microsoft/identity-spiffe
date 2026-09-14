package protocols

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"gopkg.in/yaml.v3"

	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/ca"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/mtls"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/oauth"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/rbac"
)

const (
	caller   = "spiffe://matrix.test/caller"
	serverID = "spiffe://matrix.test/server"
	issuer   = "https://login.microsoftonline.com/fixture-tenant/v2.0"
	audience = "fixture-resource"
)

func TestMain(m *testing.M) {
	// Production logs may contain identity or token-derived fields. The adapter
	// reports typed Go outcomes only; raw logs are not needed for these assertions.
	log.SetOutput(io.Discard)
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("outbound HTTP is disabled outside the local fixture")
	})
	os.Exit(m.Run())
}

func must[T any](t *testing.T, value T, err error) T {
	t.Helper()
	if err != nil {
		t.Fatal("fixture setup failed:", err)
	}
	return value
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type identityFixture struct {
	key       *rsa.PrivateKey
	mu        sync.Mutex
	policies  any
	outage    bool
	oidcCalls int
}

func newIdentityFixture(t *testing.T) *identityFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	f := &identityFixture{key: must(t, key, err), policies: []any{}}
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		var response any
		switch req.URL.Path {
		case "/fixture-tenant/v2.0/.well-known/openid-configuration":
			f.oidcCalls++
			response = map[string]any{"jwks_uri": "https://login.microsoftonline.com/fixture-jwks"}
		case "/fixture-jwks":
			response = map[string]any{"keys": []any{map[string]any{
				"kid": "local-rsa", "kty": "RSA", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes()),
			}}}
		case "/fixture-tenant/oauth2/v2.0/token":
			response = map[string]any{"access_token": "local-fixture-only", "expires_in": 3600}
		case "/beta/identity/conditionalAccess/policies":
			if f.outage {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"fixture unavailable"}`))
				return
			}
			response = map[string]any{"value": f.policies}
		default:
			t.Errorf("unexpected local fixture route")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("fixture response failed")
		}
	}))
	target, err := url.Parse(endpoint.URL)
	must(t, target, err)
	transport := &http.Transport{Proxy: nil}
	previous := http.DefaultTransport
	// These production clients have fixed cloud URLs. Re-route their HTTP I/O
	// exclusively to loopback; JWT parsing, signature checks and Graph parsing
	// are still the unmodified production implementations.
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Scheme != "https" || (req.URL.Host != "login.microsoftonline.com" && req.URL.Host != "graph.microsoft.com") {
			t.Errorf("unexpected outbound HTTP destination blocked")
			return nil, fmt.Errorf("non-fixture network destination blocked")
		}
		copyReq := req.Clone(req.Context())
		copyURL := *req.URL
		copyURL.Scheme, copyURL.Host = target.Scheme, target.Host
		copyReq.URL = &copyURL
		return transport.RoundTrip(copyReq)
	})
	t.Cleanup(func() {
		http.DefaultTransport = previous
		transport.CloseIdleConnections()
		endpoint.Close()
	})
	return f
}

func (f *identityFixture) validator() *oauth.Validator {
	return oauth.NewValidator(&oauth.Config{
		TenantID: "fixture-tenant", Audience: audience, IssuerV2: issuer,
		IssuerV1: "https://sts.windows.net/fixture-tenant/", JWKSCacheTTL: 3600,
	})
}

func (f *identityFixture) token(t *testing.T, mutate func(jwt.MapClaims), badKey bool) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": issuer, "aud": audience, "sub": "fixture-subject",
		"roles": []string{"read", "write"}, "iat": time.Now().Add(-time.Minute).Unix(),
		"nbf": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "local-rsa"
	key := f.key
	if badKey {
		newKey, err := rsa.GenerateKey(rand.Reader, 2048)
		key = must(t, newKey, err)
	}
	signed, err := token.SignedString(key)
	return must(t, signed, err)
}

func graphPolicy(state string, levels any, controls ...string) map[string]any {
	return map[string]any{
		"id": "fixture-policy", "displayName": "local policy", "state": state,
		"conditions":    map[string]any{"agentIdRiskLevels": levels},
		"grantControls": map[string]any{"builtInControls": controls},
	}
}

func (f *identityFixture) cache(t *testing.T, interval time.Duration) *ca.PolicyCache {
	t.Helper()
	client := ca.NewGraphClient("fixture-tenant", "fixture-client", "fixture-only-not-a-credential")
	cache := ca.NewPolicyCache(client, interval)
	cache.Start()
	t.Cleanup(cache.Stop)
	return cache
}

func basePolicy() rbac.Policy {
	return rbac.Policy{
		Version: "3.0", TrustDomain: "matrix.test", DefaultAction: rbac.ActionDeny,
		Policies: []rbac.CallerPolicy{{
			Name: "fixture", SpiffeID: caller, EntraAgentID: "fixture-agent",
			CA: rbac.CAPolicy{AgentState: "enabled", AgentTag: "Finance"},
			Rules: []rbac.Rule{
				{Path: "/private", Methods: []string{"*"}, Action: rbac.ActionDeny},
				{Path: "/read", Methods: []string{"GET", "POST"}, Action: rbac.ActionAllow,
					RequireJWT: true, RequiredRoles: []string{"read"}},
				{Path: "/upload", Methods: []string{"POST"}, Action: rbac.ActionAllow,
					RequireJWT: true, RequiredRoles: []string{"write"}},
			},
		}},
	}
}

func engine(t *testing.T, p rbac.Policy, validator oauth.JWTValidator, risk *rbac.RiskStore, tags *rbac.TagStore, cache *ca.PolicyCache) *rbac.Engine {
	t.Helper()
	data, err := yaml.Marshal(p)
	must(t, data, err)
	store := rbac.NewPolicyStore()
	if err := store.LoadFromBytes(data); err != nil {
		t.Fatal("fixture policy rejected:", err)
	}
	return rbac.NewEngine(store, validator, risk, tags, rbac.WithCAPolicyCache(cache))
}

type certificateAuthority struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
}

func newCA(t *testing.T) certificateAuthority {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, pub, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ephemeral test CA"},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	must(t, der, err)
	cert, err := x509.ParseCertificate(der)
	return certificateAuthority{must(t, cert, err), key}
}

func (ca certificateAuthority) svid(t *testing.T, identity string, expired bool) *x509svid.SVID {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, pub, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "test workload"},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	var id spiffeid.ID
	if identity != "" {
		uri, err := url.Parse(identity)
		template.URIs = []*url.URL{must(t, uri, err)}
		id, err = spiffeid.FromString(identity)
		must(t, id, err)
	}
	if expired {
		template.NotAfter = time.Now().Add(-time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, pub, ca.key)
	must(t, der, err)
	cert, err := x509.ParseCertificate(der)
	return &x509svid.SVID{ID: id, Certificates: []*x509.Certificate{must(t, cert, err)}, PrivateKey: key}
}

func tlsPair(t *testing.T, clientIdentity string, expired, untrusted bool) (*tls.Config, *tls.Config, *mtls.DynamicAuthorizer) {
	t.Helper()
	ca := newCA(t)
	clientCA := ca
	if untrusted {
		clientCA = newCA(t)
	}
	serverSVID := ca.svid(t, serverID, false)
	clientSVID := clientCA.svid(t, clientIdentity, expired)
	domain := spiffeid.RequireTrustDomainFromString("matrix.test")
	bundle := x509bundle.FromX509Authorities(domain, []*x509.Certificate{ca.cert})
	auth := mtls.NewDynamicAuthorizer([]spiffeid.ID{spiffeid.RequireFromString(caller)}, nil)
	serverConfig := tlsconfig.MTLSServerConfig(serverSVID, bundle,
		func(id spiffeid.ID, _ [][]*x509.Certificate) error { return auth.Authorize(id) })
	clientConfig := tlsconfig.MTLSClientConfig(clientSVID, bundle,
		tlsconfig.AuthorizeID(spiffeid.RequireFromString(serverID)))
	if clientIdentity == "" {
		// No SVID object can represent a certificate without a URI. Present the
		// cryptographically valid certificate directly to the real TLS verifier.
		clientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &tls.Certificate{Certificate: [][]byte{clientSVID.Certificates[0].Raw}, PrivateKey: clientSVID.PrivateKey}, nil
		}
	}
	return serverConfig, clientConfig, auth
}

func assertDecision(t *testing.T, got rbac.Decision, action rbac.Action, layer, reason string, status int) {
	t.Helper()
	logDecision(t, got)
	if got.Action != action || got.EnforcementLayer != layer || got.Reason != reason || got.StatusCode != status {
		t.Fatalf("decision mismatch: got action=%s layer=%s reason=%s status=%d; expected action=%s layer=%s reason=%s status=%d",
			got.Action, got.EnforcementLayer, got.Reason, got.StatusCode, action, layer, reason, status)
	}
}

func logDecision(t *testing.T, got rbac.Decision) {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"action": got.Action, "layer": got.EnforcementLayer, "status_code": got.StatusCode,
	})
	if err != nil {
		t.Fatal("cannot encode typed decision evidence")
	}
	t.Log("PROTOCOL_EVIDENCE " + string(data))
}

func containsError(err error, part string) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), part)
}
