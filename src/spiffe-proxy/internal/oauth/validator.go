package oauth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims holds the validated JWT claims relevant to authorization.
type Claims struct {
	Issuer       string            `json:"iss"`
	Audience     string            `json:"aud"`
	Subject      string            `json:"sub"`
	Roles        []string          `json:"roles"`
	AppID        string            `json:"appid"`
	AZP          string            `json:"azp"`
	OID          string            `json:"oid"`
	TenantID     string            `json:"tid"`
	CustomClaims map[string]string `json:"custom_claims,omitempty"`
}

// JWTValidator is the interface for JWT validation. The RBAC engine
// uses this to check tokens when a rule has require_jwt: true.
type JWTValidator interface {
	ValidateJWT(token string) (*Claims, error)
	Status() ValidatorStatus
}

// ValidatorStatus reports the current state of the OAuth validator,
// used by the /mgmt/oauth-status endpoint.
type ValidatorStatus struct {
	ConfigLoaded    bool       `json:"config_loaded"`
	JWKSCached      bool       `json:"jwks_cached"`
	LastJWKSRefresh *time.Time `json:"last_jwks_refresh,omitempty"`
	KeyCount        int        `json:"key_count"`
	TenantID        string     `json:"tenant_id"`
	Audience        string     `json:"audience"`
}

// Validator implements JWT validation using Entra ID JWKS.
type Validator struct {
	config      *Config
	mu          sync.RWMutex
	keys        map[string]*rsa.PublicKey
	lastRefresh time.Time
	httpClient  *http.Client
	fetchMu     sync.Mutex // serializes concurrent JWKS fetches (prevents thundering herd)
}

// NewValidator creates a JWT validator from the given config.
// JWKS is fetched lazily on first validation call.
func NewValidator(config *Config) *Validator {
	return &Validator{
		config:     config,
		keys:       make(map[string]*rsa.PublicKey),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// JWKS response structures (RFC 7517).
type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// fetchJWKS retrieves the JWKS from the Entra ID OIDC discovery endpoint
// and caches the RSA public keys for JWT signature verification.
func (v *Validator) fetchJWKS() error {
	// Step 1: Fetch OIDC discovery document to get jwks_uri.
	oidcURL := fmt.Sprintf(
		"https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration",
		v.config.TenantID,
	)
	resp, err := v.httpClient.Get(oidcURL)
	if err != nil {
		return fmt.Errorf("fetch OIDC discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("OIDC discovery returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var discovery struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return fmt.Errorf("parse OIDC discovery: %w", err)
	}
	if discovery.JWKSURI == "" {
		return fmt.Errorf("no jwks_uri in OIDC discovery")
	}

	// Step 2: Fetch the JWKS.
	jwksResp, err := v.httpClient.Get(discovery.JWKSURI)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer jwksResp.Body.Close()

	if jwksResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(jwksResp.Body, 512))
		return fmt.Errorf("JWKS endpoint returned HTTP %d: %s", jwksResp.StatusCode, string(body))
	}

	var jwks jwksResponse
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}

	// Step 3: Parse RSA signing keys.
	keys := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.Use != "sig" {
			continue
		}
		pubKey, err := parseRSAPublicKey(key)
		if err != nil {
			log.Printf("[OAuth] Warning: failed to parse key %s: %v", key.Kid, err)
			continue
		}
		keys[key.Kid] = pubKey
	}

	if len(keys) == 0 {
		return fmt.Errorf("no valid RSA signing keys in JWKS")
	}

	v.mu.Lock()
	v.keys = keys
	v.lastRefresh = time.Now()
	v.mu.Unlock()

	log.Printf("[OAuth] JWKS refreshed: %d keys cached", len(keys))
	return nil
}

func parseRSAPublicKey(key jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("decode N: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("decode E: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// getKey returns the RSA public key for the given kid (key ID).
// If not found and the cache is stale (older than JWKSCacheTTL), re-fetches JWKS and retries.
// Uses fetchMu to serialize concurrent fetches and prevent thundering herd on JWKS rotation.
func (v *Validator) getKey(kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key, ok := v.keys[kid]
	cacheAge := time.Since(v.lastRefresh)
	v.mu.RUnlock()

	if ok {
		return key, nil
	}

	// Key not found — re-fetch if cache is old enough or never fetched.
	cacheTTL := time.Duration(v.config.JWKSCacheTTL) * time.Second
	if cacheTTL <= 0 {
		cacheTTL = 24 * time.Hour
	}
	if cacheAge > cacheTTL || v.lastRefresh.IsZero() {
		// Serialize concurrent fetches to avoid thundering herd.
		v.fetchMu.Lock()
		// Double-check: another goroutine may have refreshed while we waited.
		v.mu.RLock()
		key, ok = v.keys[kid]
		lastRefresh := v.lastRefresh
		v.mu.RUnlock()
		if ok {
			v.fetchMu.Unlock()
			return key, nil
		}
		// Another goroutine may have refreshed but the key still wasn't found.
		if !lastRefresh.IsZero() && time.Since(lastRefresh) < cacheTTL {
			v.fetchMu.Unlock()
			return nil, fmt.Errorf("key %q not found in JWKS", kid)
		}
		err := v.fetchJWKS()
		v.fetchMu.Unlock()
		if err != nil {
			return nil, fmt.Errorf("JWKS refresh failed: %w", err)
		}
		v.mu.RLock()
		key, ok = v.keys[kid]
		v.mu.RUnlock()
		if ok {
			return key, nil
		}
	}

	return nil, fmt.Errorf("key %q not found in JWKS", kid)
}

// keyFunc is the jwt.Keyfunc used by the JWT parser to look up signing keys.
func (v *Validator) keyFunc(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("missing kid in token header")
	}

	return v.getKey(kid)
}

// entraTokenClaims maps the JWT payload for Entra ID client credentials tokens.
type entraTokenClaims struct {
	jwt.RegisteredClaims
	Roles    []string `json:"roles"`
	AppID    string   `json:"appid"`
	AZP      string   `json:"azp"`
	OID      string   `json:"oid"`
	TenantID string   `json:"tid"`
	Version  string   `json:"ver"`
}

// ValidateJWT validates an Entra ID JWT token: signature, issuer, audience.
// Returns the extracted claims on success.
func (v *Validator) ValidateJWT(tokenString string) (*Claims, error) {
	if v.config.TenantID == "" || v.config.Audience == "" {
		return nil, fmt.Errorf("OAuth not configured (missing tenant_id or audience)")
	}

	// Lazy JWKS fetch on first call (serialized to prevent thundering herd).
	v.mu.RLock()
	needsFetch := len(v.keys) == 0
	v.mu.RUnlock()
	if needsFetch {
		v.fetchMu.Lock()
		v.mu.RLock()
		stillNeedsFetch := len(v.keys) == 0
		v.mu.RUnlock()
		if stillNeedsFetch {
			if err := v.fetchJWKS(); err != nil {
				v.fetchMu.Unlock()
				return nil, fmt.Errorf("initial JWKS fetch failed: %w", err)
			}
		}
		v.fetchMu.Unlock()
	}

	// Parse and verify JWT signature.
	claims := &entraTokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, v.keyFunc,
		jwt.WithValidMethods([]string{"RS256"}),
	)
	if err != nil {
		return nil, fmt.Errorf("JWT validation failed: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Validate issuer — accept both v1.0 and v2.0 Entra formats.
	actualIssuer := claims.Issuer
	validIssuers := []string{v.config.IssuerV1, v.config.IssuerV2}
	issuerValid := false
	for _, valid := range validIssuers {
		if valid != "" && actualIssuer == valid {
			issuerValid = true
			break
		}
	}
	if !issuerValid {
		return nil, fmt.Errorf("invalid issuer: %s", actualIssuer)
	}

	// Validate audience — accept with or without api:// prefix.
	actualAudience := ""
	if len(claims.Audience) > 0 {
		actualAudience = claims.Audience[0]
	}
	validAudiences := []string{
		v.config.Audience,
		"api://" + v.config.Audience,
	}
	if strings.HasPrefix(v.config.Audience, "api://") {
		validAudiences = append(validAudiences, strings.TrimPrefix(v.config.Audience, "api://"))
	}
	audienceValid := false
	for _, valid := range validAudiences {
		if valid != "" && actualAudience == valid {
			audienceValid = true
			break
		}
	}
	if !audienceValid {
		return nil, fmt.Errorf("invalid audience: %s", actualAudience)
	}

	// Extract custom claims with known prefixes (e.g., github_*, aim_*)
	customClaims := make(map[string]string)
	if unverified, _, _ := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{}); unverified != nil {
		if mc, ok := unverified.Claims.(jwt.MapClaims); ok {
			for key, val := range mc {
				if strings.HasPrefix(key, "github_") || strings.HasPrefix(key, "aim_") {
					if strVal, ok := val.(string); ok {
						customClaims[key] = strVal
					}
				}
			}
		}
	}

	return &Claims{
		Issuer:       actualIssuer,
		Audience:     actualAudience,
		Subject:      claims.Subject,
		Roles:        claims.Roles,
		AppID:        claims.AppID,
		AZP:         claims.AZP,
		OID:          claims.OID,
		TenantID:     claims.TenantID,
		CustomClaims: customClaims,
	}, nil
}

// Status returns the current validator state for the management API.
func (v *Validator) Status() ValidatorStatus {
	v.mu.RLock()
	defer v.mu.RUnlock()

	status := ValidatorStatus{
		ConfigLoaded: true,
		JWKSCached:   len(v.keys) > 0,
		KeyCount:     len(v.keys),
		TenantID:     v.config.TenantID,
		Audience:     v.config.Audience,
	}
	if !v.lastRefresh.IsZero() {
		t := v.lastRefresh
		status.LastJWKSRefresh = &t
	}
	return status
}
