// Package oauth provides JWT validation for Entra Agent Identity OAuth2 tokens.
// This is Layer 3 of the AIM enforcement stack (mTLS → RBAC → OAuth/JWT).
package oauth

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds OAuth/JWKS configuration for JWT validation.
type Config struct {
	TenantID     string `yaml:"tenant_id"`
	Audience     string `yaml:"audience"`
	IssuerV1     string `yaml:"issuer_v1"`
	IssuerV2     string `yaml:"issuer_v2"`
	JWKSCacheTTL int    `yaml:"jwks_cache_ttl_seconds"`
}

// LoadConfig reads an oauth-config.yaml file and applies env var overrides.
// AZURE_TENANT_ID and ENTRA_OAUTH2_AUDIENCE env vars take precedence over YAML values.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read oauth config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse oauth config: %w", err)
	}

	// Env var overrides (deploy.sh injects these at container startup).
	if v := os.Getenv("AZURE_TENANT_ID"); v != "" {
		cfg.TenantID = v
	}
	if v := os.Getenv("ENTRA_OAUTH2_AUDIENCE"); v != "" {
		cfg.Audience = v
	}

	// Derive issuers from tenant ID if not explicitly set.
	// Entra ID tokens use v1.0 or v2.0 issuer format depending on the app manifest.
	if cfg.TenantID != "" {
		if cfg.IssuerV1 == "" {
			cfg.IssuerV1 = fmt.Sprintf("https://sts.windows.net/%s/", cfg.TenantID)
		}
		if cfg.IssuerV2 == "" {
			cfg.IssuerV2 = fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", cfg.TenantID)
		}
	}

	if cfg.JWKSCacheTTL <= 0 {
		cfg.JWKSCacheTTL = 86400 // 24 hours
	}

	return &cfg, nil
}
