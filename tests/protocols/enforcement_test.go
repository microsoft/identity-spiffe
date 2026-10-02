package protocols

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/oauth"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/rbac"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func TestMTLS(t *testing.T) {
	for _, name := range []string{"allowed", "disallowed", "absent", "untrusted", "expired", "no_uri", "revoked"} {
		t.Run(name, func(t *testing.T) {
			identity := caller
			if name == "disallowed" {
				identity = "spiffe://matrix.test/other"
			}
			if name == "no_uri" {
				identity = ""
			}
			serverConfig, clientConfig, auth := tlsPair(t, identity, name == "expired", name == "untrusted")
			if name == "revoked" {
				auth.Remove(spiffeid.RequireFromString(caller))
			}
			if name == "absent" {
				clientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &tls.Certificate{}, nil
				}
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			must(t, listener, err)
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					done <- err
					return
				}
				done <- tls.Server(conn, serverConfig).Handshake()
			}()
			conn, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
			must(t, conn, err)
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			clientErr := tls.Client(conn, clientConfig).Handshake()
			serverErr := <-done
			if name == "allowed" {
				if clientErr != nil || serverErr != nil {
					t.Fatal("trusted mutual TLS handshake did not succeed")
				}
				return
			}
			// Assert the server-side security reason: a timeout, refused socket
			// or a client transport failure alone is never a passing rejection.
			reasons := map[string]string{
				"disallowed": "not in the allow list", "revoked": "not in the allow list",
				"absent":    "client didn't provide a certificate",
				"untrusted": "unknown authority", "expired": "expired", "no_uri": "uri",
			}
			if !containsError(serverErr, reasons[name]) {
				t.Fatalf("expected TLS rejection category %q; got %v", reasons[name], serverErr)
			}
		})
	}
}

func TestEnforcement(t *testing.T) {
	jwtErrorCategories := map[string]string{
		"jwt_malformed":      "token is malformed",
		"jwt_bad_signature":  "token signature is invalid",
		"jwt_wrong_audience": "invalid audience:",
		"jwt_wrong_issuer":   "invalid issuer:",
		"jwt_expired":        "token is expired",
		"jwt_future":         "token is not valid yet",
		"jwt_no_expiry":      "exp claim is required",
	}
	names := []string{
		"allowed", "unknown_caller", "wrong_method", "wrong_route", "normalized_deny", "prefix_boundary",
		"jwt_missing", "jwt_malformed", "jwt_bad_signature", "jwt_wrong_audience", "jwt_wrong_issuer",
		"jwt_expired", "jwt_future", "jwt_no_expiry", "role_missing", "role_partial", "validator_absent",
		"rbac_before_oauth", "ca_before_rbac", "ca_before_oauth",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			f := newIdentityFixture(t)
			p := basePolicy()
			id, method, path := caller, "GET", "/read"
			action, layer, reason, status := rbac.ActionAllow, rbac.LayerOAuth, "matched_rule", 0
			var mutate func(jwt.MapClaims)
			switch name {
			case "jwt_wrong_audience":
				mutate = func(c jwt.MapClaims) { c["aud"] = "other-resource" }
			case "jwt_wrong_issuer":
				mutate = func(c jwt.MapClaims) { c["iss"] = "https://invalid.example/" }
			case "jwt_expired":
				mutate = func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }
			case "jwt_future":
				mutate = func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }
			case "jwt_no_expiry":
				mutate = func(c jwt.MapClaims) { delete(c, "exp") }
			case "role_missing", "role_partial":
				mutate = func(c jwt.MapClaims) { c["roles"] = []string{"write"} }
			}
			token := f.token(t, mutate, name == "jwt_bad_signature")
			var validator oauth.JWTValidator = f.validator()
			switch name {
			case "unknown_caller":
				id, reason = "spiffe://matrix.test/unknown", "no_caller_policy"
			case "wrong_method":
				method, reason = "DELETE", "no_matching_rule"
			case "wrong_route":
				path, reason = "/unknown", "no_matching_rule"
			case "normalized_deny":
				path, reason = "/unused/../%70rivate", "matched_rule"
			case "prefix_boundary":
				p.Policies[0].SpiffeID = ""
				p.Policies[0].SpiffeIDPrefix = caller
				id, reason = caller+"-sibling", "no_caller_policy"
			case "jwt_missing":
				token, reason = "", "jwt_required"
			case "jwt_malformed":
				token = "not-a-jwt"
			case "role_partial":
				p.Policies[0].Rules[1].RequiredRoles = []string{"write", "read"}
			case "validator_absent":
				validator = nil
			case "rbac_before_oauth":
				token, path = "not-a-jwt", "/private"
			case "ca_before_rbac", "ca_before_oauth":
				p.AdminGovernance.Enabled = true
				p.Policies[0].CA.AgentState = "disabled"
				token = "not-a-jwt"
				if name == "ca_before_rbac" {
					path = "/private"
				}
			}
			switch name {
			case "unknown_caller", "wrong_method", "wrong_route", "normalized_deny", "prefix_boundary", "rbac_before_oauth":
				action, layer, status = rbac.ActionDeny, rbac.LayerRBAC, 403
			case "jwt_missing":
				action, layer, status = rbac.ActionDeny, rbac.LayerOAuth, 401
			case "jwt_malformed", "jwt_bad_signature", "jwt_wrong_audience", "jwt_wrong_issuer", "jwt_expired", "jwt_future", "jwt_no_expiry":
				action, layer, reason, status = rbac.ActionDeny, rbac.LayerOAuth, "jwt_invalid", 401
			case "role_missing", "role_partial":
				action, layer, reason, status = rbac.ActionDeny, rbac.LayerOAuth, "insufficient_roles", 403
			case "validator_absent":
				action, layer, reason, status = rbac.ActionDeny, rbac.LayerOAuth, "jwt_validator_unavailable", 503
			case "ca_before_rbac", "ca_before_oauth":
				action, layer, reason, status = rbac.ActionDeny, rbac.LayerCA, "agent_disabled", 403
			}
			errorCategory := jwtErrorCategories[name]
			if errorCategory != "" || name == "role_missing" || name == "role_partial" {
				// Prove this exact fixture/validator can validate a control token.
				// A metadata outage must not masquerade as the expected JWT denial.
				control, err := validator.ValidateJWT(f.token(t, nil, false))
				if err != nil || control == nil || control.Audience != audience || control.Issuer != issuer {
					t.Fatal("valid control token failed to initialize this validator")
				}
				validatorStatus := validator.Status()
				if !validatorStatus.ConfigLoaded || !validatorStatus.JWKSCached ||
					validatorStatus.KeyCount != 1 || validatorStatus.LastJWKSRefresh == nil {
					t.Fatal("control token did not establish successful JWKS initialization")
				}
			}
			got := engine(t, p, validator, nil, nil, nil).Evaluate(id, method, path, token)
			assertDecision(t, got, action, layer, reason, status)
			if errorCategory != "" && !strings.Contains(got.JWTError, errorCategory) {
				t.Fatalf("JWT rejection did not match required category %q", errorCategory)
			}
			if (name == "role_missing" || name == "role_partial") && !got.JWTValid {
				t.Fatal("role rejection was not based on a successfully validated JWT")
			}
			if name == "rbac_before_oauth" || name == "ca_before_rbac" || name == "ca_before_oauth" {
				f.mu.Lock()
				calls := f.oidcCalls
				f.mu.Unlock()
				if calls != 0 {
					t.Fatal("later OAuth layer unexpectedly ran")
				}
			}
			if name == "allowed" && (!got.JWTValid || !validator.Status().JWKSCached || validator.Status().KeyCount != 1) {
				t.Fatal("allow did not establish JWT validity")
			}
		})
	}
}
