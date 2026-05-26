// Package ca implements Conditional Access policy evaluation using
// Microsoft Graph API. It fetches CA policies from Entra, parses
// agentIdRiskLevels conditions, and determines which risk levels
// should block callers based on live CA policy state.
//
// Currently evaluates: agentIdRiskLevels (risk enforcement)
// TODO: Evaluate applicationFilter/servicePrincipalFilter (tag enforcement from CA)
package ca

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const graphBeta = "https://graph.microsoft.com/beta"

// GraphClient handles OAuth2 client credentials authentication to
// Microsoft Graph API. It caches tokens and refreshes them automatically.
type GraphClient struct {
	tenantID     string
	clientID     string
	clientSecret string
	httpClient   *http.Client

	mu       sync.Mutex
	token    string
	expireAt time.Time
}

// NewGraphClient creates a Graph API client. Returns nil if credentials
// are empty (Graph integration disabled).
func NewGraphClient(tenantID, clientID, clientSecret string) *GraphClient {
	if tenantID == "" || clientID == "" || clientSecret == "" {
		return nil
	}
	return &GraphClient{
		tenantID:     tenantID,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   &http.Client{Timeout: 15 * time.Second},
	}
}

// getToken returns a cached or freshly acquired access token.
func (c *GraphClient) getToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.expireAt) {
		return c.token, nil
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", c.tenantID)
	data := url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
		"grant_type":    {"client_credentials"},
	}

	resp, err := c.httpClient.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		truncated := string(body)
		if len(truncated) > 200 {
			truncated = truncated[:200]
		}
		return "", fmt.Errorf("token request returned %d: %s", resp.StatusCode, truncated)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("token response parse failed: %w", err)
	}

	c.token = result.AccessToken
	// Refresh 60 seconds before expiry
	c.expireAt = time.Now().Add(time.Duration(result.ExpiresIn-60) * time.Second)
	return c.token, nil
}

// Get performs an authenticated GET request to the given URL.
func (c *GraphClient) Get(reqURL string) ([]byte, error) {
	token, err := c.getToken()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s failed: %w", reqURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", reqURL, err)
	}

	if resp.StatusCode != 200 {
		truncated := string(body)
		if len(truncated) > 200 {
			truncated = truncated[:200]
		}
		return nil, fmt.Errorf("GET %s returned %d: %s", reqURL, resp.StatusCode, truncated)
	}

	return body, nil
}
