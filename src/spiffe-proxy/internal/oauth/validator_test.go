package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testSetup creates a test JWKS server and a validator configured to use it.
func testSetup(t *testing.T) (*rsa.PrivateKey, *httptest.Server, *Validator) {
	t.Helper()

	// Generate RSA key pair for signing test tokens.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	kid := "test-kid-1"

	// Build a JWKS response with the public key.
	jwksJSON := buildJWKS(t, &privateKey.PublicKey, kid)

	// Start a test HTTP server that serves OIDC discovery + JWKS.
	mux := http.NewServeMux()
	mux.HandleFunc("/test-tenant/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"jwks_uri": "http://" + r.Host + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	})

	server := httptest.NewServer(mux)

	// Create validator that uses the test server instead of real Entra endpoints.
	cfg := &Config{
		TenantID:     "test-tenant",
		Audience:     "api://test-app",
		IssuerV1:     "https://sts.windows.net/test-tenant/",
		IssuerV2:     "https://login.microsoftonline.com/test-tenant/v2.0",
		JWKSCacheTTL: 86400,
	}
	v := NewValidator(cfg)
	v.httpClient = server.Client()

	// Override the OIDC URL to point to test server.
	// We achieve this by pre-loading the JWKS directly.
	pubKey := &privateKey.PublicKey
	v.mu.Lock()
	v.keys = map[string]*rsa.PublicKey{kid: pubKey}
	v.lastRefresh = time.Now()
	v.mu.Unlock()

	return privateKey, server, v
}

func buildJWKS(t *testing.T, pub *rsa.PublicKey, kid string) []byte {
	t.Helper()
	nBase64 := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	eBase64 := base64.RawURLEncoding.EncodeToString(eBytes)

	jwks := map[string]interface{}{
		"keys": []map[string]string{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": kid,
				"n":   nBase64,
				"e":   eBase64,
				"alg": "RS256",
			},
		},
	}
	data, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("Failed to marshal JWKS: %v", err)
	}
	return data
}

func signToken(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}
	return tokenString
}

func TestValidateJWT_ValidToken(t *testing.T) {
	privateKey, server, v := testSetup(t)
	defer server.Close()

	tokenString := signToken(t, privateKey, "test-kid-1", jwt.MapClaims{
		"iss":   "https://login.microsoftonline.com/test-tenant/v2.0",
		"aud":   "api://test-app",
		"sub":   "test-subject",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"roles": []string{"Budget.Read", "Budget.Submit"},
		"oid":   "agent-oid-123",
		"tid":   "test-tenant",
	})

	claims, err := v.ValidateJWT(tokenString)
	if err != nil {
		t.Fatalf("ValidateJWT failed: %v", err)
	}
	if claims.Audience != "api://test-app" {
		t.Errorf("Expected audience 'api://test-app', got %q", claims.Audience)
	}
	if len(claims.Roles) != 2 || claims.Roles[0] != "Budget.Read" {
		t.Errorf("Expected roles [Budget.Read, Budget.Submit], got %v", claims.Roles)
	}
	if claims.OID != "agent-oid-123" {
		t.Errorf("Expected OID 'agent-oid-123', got %q", claims.OID)
	}
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	privateKey, server, v := testSetup(t)
	defer server.Close()

	tokenString := signToken(t, privateKey, "test-kid-1", jwt.MapClaims{
		"iss": "https://login.microsoftonline.com/test-tenant/v2.0",
		"aud": "api://test-app",
		"exp": time.Now().Add(-time.Hour).Unix(), // expired
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	})

	_, err := v.ValidateJWT(tokenString)
	if err == nil {
		t.Error("Expected error for expired token")
	}
}

func TestValidateJWT_ExpirationRequired(t *testing.T) {
	privateKey, server, v := testSetup(t)
	defer server.Close()

	now := time.Now()
	cases := []struct {
		name    string
		exp     interface{}
		omit    bool
		wantErr error
	}{
		{name: "missing", omit: true, wantErr: jwt.ErrTokenRequiredClaimMissing},
		{name: "null", exp: nil, wantErr: jwt.ErrTokenRequiredClaimMissing},
		{name: "invalid_string", exp: "not-a-date", wantErr: jwt.ErrTokenMalformed},
		{name: "boolean", exp: true, wantErr: jwt.ErrTokenMalformed},
		{name: "array", exp: []int{1}, wantErr: jwt.ErrTokenMalformed},
		{name: "object", exp: map[string]int{"seconds": 1}, wantErr: jwt.ErrTokenMalformed},
		{name: "zero", exp: 0, wantErr: jwt.ErrTokenExpired},
		{name: "expired", exp: now.Add(-time.Hour).Unix(), wantErr: jwt.ErrTokenExpired},
		{name: "valid", exp: now.Add(time.Hour).Unix()},
		{name: "fractional", exp: float64(now.Add(time.Hour).Unix()) + 0.5},
		{name: "numeric_string", exp: fmt.Sprintf("%d", now.Add(time.Hour).Unix())},
		{name: "nonfinite_string", exp: "NaN", wantErr: jwt.ErrTokenMalformed},
		{name: "infinite_string", exp: "Infinity", wantErr: jwt.ErrTokenMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// No iat/nbf: requiring exp must not make other time claims mandatory.
			payload := jwt.MapClaims{
				"iss": "https://login.microsoftonline.com/test-tenant/v2.0",
				"aud": "api://test-app",
			}
			if !tc.omit {
				payload["exp"] = tc.exp
			}
			claims, err := v.ValidateJWT(signToken(t, privateKey, "test-kid-1", payload))
			if tc.wantErr == nil {
				if err != nil || claims == nil {
					t.Fatalf("valid expiration rejected: %v", err)
				}
			} else {
				if claims != nil || !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected expiration error %v and no claims; got %v", tc.wantErr, err)
				}
				if errors.Is(tc.wantErr, jwt.ErrTokenRequiredClaimMissing) &&
					!strings.Contains(err.Error(), "exp claim is required") {
					t.Fatalf("missing expiration was not explicitly identified: %v", err)
				}
			}
		})
	}
}

func TestValidateJWT_WrongAudience(t *testing.T) {
	privateKey, server, v := testSetup(t)
	defer server.Close()

	tokenString := signToken(t, privateKey, "test-kid-1", jwt.MapClaims{
		"iss": "https://login.microsoftonline.com/test-tenant/v2.0",
		"aud": "api://wrong-app",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	_, err := v.ValidateJWT(tokenString)
	if err == nil {
		t.Error("Expected error for wrong audience")
	}
}

func TestValidateJWT_WrongIssuer(t *testing.T) {
	privateKey, server, v := testSetup(t)
	defer server.Close()

	tokenString := signToken(t, privateKey, "test-kid-1", jwt.MapClaims{
		"iss": "https://evil.example.com/",
		"aud": "api://test-app",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	_, err := v.ValidateJWT(tokenString)
	if err == nil {
		t.Error("Expected error for wrong issuer")
	}
}

func TestValidateJWT_MalformedToken(t *testing.T) {
	_, server, v := testSetup(t)
	defer server.Close()

	_, err := v.ValidateJWT("not-a-jwt")
	if err == nil {
		t.Error("Expected error for malformed token")
	}
}

func TestValidateJWT_V1Issuer(t *testing.T) {
	privateKey, server, v := testSetup(t)
	defer server.Close()

	// v1.0 issuer format should also be accepted.
	tokenString := signToken(t, privateKey, "test-kid-1", jwt.MapClaims{
		"iss":   "https://sts.windows.net/test-tenant/",
		"aud":   "api://test-app",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"roles": []string{"Budget.Read"},
	})

	claims, err := v.ValidateJWT(tokenString)
	if err != nil {
		t.Fatalf("v1.0 issuer should be accepted: %v", err)
	}
	if claims.Issuer != "https://sts.windows.net/test-tenant/" {
		t.Errorf("Expected v1 issuer, got %q", claims.Issuer)
	}
}

func TestValidateJWT_MissingRoles(t *testing.T) {
	privateKey, server, v := testSetup(t)
	defer server.Close()

	// Token with no roles claim — should still validate (roles check is engine's job).
	tokenString := signToken(t, privateKey, "test-kid-1", jwt.MapClaims{
		"iss": "https://login.microsoftonline.com/test-tenant/v2.0",
		"aud": "api://test-app",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	claims, err := v.ValidateJWT(tokenString)
	if err != nil {
		t.Fatalf("Token without roles should still validate: %v", err)
	}
	if len(claims.Roles) != 0 {
		t.Errorf("Expected empty roles, got %v", claims.Roles)
	}
}

func TestStatus_NoKeys(t *testing.T) {
	cfg := &Config{TenantID: "t", Audience: "a"}
	v := NewValidator(cfg)
	s := v.Status()
	if s.JWKSCached {
		t.Error("Expected JWKSCached to be false")
	}
	if s.KeyCount != 0 {
		t.Errorf("Expected 0 keys, got %d", s.KeyCount)
	}
}

func TestStatus_WithKeys(t *testing.T) {
	_, server, v := testSetup(t)
	defer server.Close()

	s := v.Status()
	if !s.JWKSCached {
		t.Error("Expected JWKSCached to be true")
	}
	if s.KeyCount != 1 {
		t.Errorf("Expected 1 key, got %d", s.KeyCount)
	}
	if s.TenantID != "test-tenant" {
		t.Errorf("Expected tenant 'test-tenant', got %q", s.TenantID)
	}
}

func TestParseRSAPublicKey(t *testing.T) {
	// Generate a key, serialize, parse back, and verify it works.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key gen: %v", err)
	}
	pub := &privateKey.PublicKey

	key := jwkKey{
		Kid: "test",
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		Use: "sig",
	}

	parsed, err := parseRSAPublicKey(key)
	if err != nil {
		t.Fatalf("parseRSAPublicKey: %v", err)
	}

	if parsed.N.Cmp(pub.N) != 0 {
		t.Error("N mismatch")
	}
	if parsed.E != pub.E {
		t.Errorf("E mismatch: got %d, want %d", parsed.E, pub.E)
	}
}
