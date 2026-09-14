package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/mtls"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/oauth"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

const (
	callerID = "spiffe://stack.test/caller"
	serverID = "spiffe://stack.test/server"
	issuer   = "https://login.microsoftonline.com/stack-tenant/v2.0"
	audience = "stack-budget-api"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Only issuance and fixed-host Graph/OIDC HTTP I/O are synthetic. Validation,
// Graph parsing, policy evaluation and TLS verification are production code.
type identityFixture struct {
	key, wrongKey *rsa.PrivateKey
	mu            sync.Mutex
	outage        bool
	server        *httptest.Server
	previous      http.RoundTripper
	transport     *http.Transport
}

func newIdentityFixture() (*identityFixture, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	f := &identityFixture{key: key, wrongKey: wrongKey, previous: http.DefaultTransport,
		transport: &http.Transport{Proxy: nil, ResponseHeaderTimeout: 3 * time.Second}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	target, _ := url.Parse(f.server.URL)
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Scheme != "https" || (req.URL.Host != "login.microsoftonline.com" && req.URL.Host != "graph.microsoft.com") {
			return nil, fmt.Errorf("non-fixture outbound HTTP is disabled")
		}
		copyReq := req.Clone(req.Context())
		copyURL := *req.URL
		copyURL.Scheme, copyURL.Host = target.Scheme, target.Host
		copyReq.URL = &copyURL
		return f.transport.RoundTrip(copyReq)
	})
	return f, nil
}

func (f *identityFixture) Close() {
	f.server.Close()
	f.transport.CloseIdleConnections()
	http.DefaultTransport = f.previous
}

func (f *identityFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var value any
	switch r.URL.Path {
	case "/stack-tenant/v2.0/.well-known/openid-configuration":
		value = map[string]any{"jwks_uri": "https://login.microsoftonline.com/stack-jwks"}
	case "/stack-jwks":
		value = map[string]any{"keys": []any{map[string]any{
			"kid": "stack-rsa", "kty": "RSA", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes()),
		}}}
	case "/stack-tenant/oauth2/v2.0/token":
		value = map[string]any{"access_token": "synthetic-graph-only", "expires_in": 3600}
	case "/beta/identity/conditionalAccess/policies":
		if f.outage {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		value = map[string]any{"value": []any{map[string]any{
			"id": "stack-policy", "displayName": "Synthetic high-risk block", "state": "enabled",
			"conditions":    map[string]any{"agentIdRiskLevels": []string{"high"}},
			"grantControls": map[string]any{"builtInControls": []string{"block"}},
		}}}
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeJSON(w, value)
}

func (f *identityFixture) signedToken(scenario string) (string, error) {
	if scenario == "jwt_missing" {
		return "", nil
	}
	claims := jwt.MapClaims{
		"iss": issuer, "aud": audience, "sub": "synthetic-stack-caller",
		"roles": []string{"Budget.Read"}, "iat": time.Now().Add(-time.Minute).Unix(),
		"nbf": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}
	switch scenario {
	case "jwt_expired":
		claims["exp"] = time.Now().Add(-time.Hour).Unix()
	case "jwt_wrong_audience":
		claims["aud"] = "other-resource"
	case "jwt_no_expiry":
		delete(claims, "exp")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "stack-rsa"
	key := f.key
	if scenario == "jwt_wrong_signature" {
		key = f.wrongKey
	}
	return token.SignedString(key)
}

func (f *identityFixture) primedValidator() (*oauth.Validator, error) {
	validator := oauth.NewValidator(&oauth.Config{
		TenantID: "stack-tenant", Audience: audience, IssuerV2: issuer,
		IssuerV1: "https://sts.windows.net/stack-tenant/", JWKSCacheTTL: 3600,
	})
	token, err := f.signedToken("allowed")
	if err != nil {
		return nil, err
	}
	if _, err := validator.ValidateJWT(token); err != nil {
		return nil, fmt.Errorf("healthy signed-token control failed")
	}
	if !validator.Status().JWKSCached || validator.Status().KeyCount != 1 {
		return nil, fmt.Errorf("healthy control did not prime production JWKS cache")
	}
	return validator, nil
}

func tlsPair(auth *mtls.DynamicAuthorizer) (*tls.Config, *tls.Config, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic stack CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, root, root, pub, key)
	if err != nil {
		return nil, nil, err
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	issue := func(identity string) (*x509svid.SVID, error) {
		pub, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		uri, _ := url.Parse(identity)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			NotBefore:    time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
			URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, root, pub, key)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		return &x509svid.SVID{ID: spiffeid.RequireFromString(identity),
			Certificates: []*x509.Certificate{cert}, PrivateKey: private}, nil
	}
	server, err := issue(serverID)
	if err != nil {
		return nil, nil, err
	}
	client, err := issue(callerID)
	if err != nil {
		return nil, nil, err
	}
	bundle := x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("stack.test"), []*x509.Certificate{root})
	return tlsconfig.MTLSServerConfig(server, bundle,
			func(id spiffeid.ID, _ [][]*x509.Certificate) error { return auth.Authorize(id) }),
		tlsconfig.MTLSClientConfig(client, bundle, tlsconfig.AuthorizeID(spiffeid.RequireFromString(serverID))), nil
}
