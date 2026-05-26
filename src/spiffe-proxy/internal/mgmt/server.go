// Package mgmt implements the localhost-only REST management API
// for the SPIFFE sidecar gateway. It provides policy CRUD, health checks,
// metrics, and audit log access on port 9443.
package mgmt

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/project-aim/spiffe-proxy/internal/ca"
	"github.com/project-aim/spiffe-proxy/internal/logging"
	"github.com/project-aim/spiffe-proxy/internal/mtls"
	"github.com/project-aim/spiffe-proxy/internal/oauth"
	"github.com/project-aim/spiffe-proxy/internal/rbac"
	"github.com/project-aim/spiffe-proxy/internal/spiffe"
)

// Server is the management API HTTP server.
type Server struct {
	httpServer     *http.Server
	store          *rbac.PolicyStore
	logger         *logging.AccessLogger
	identity       *spiffe.WorkloadIdentity
	dynamicAuth    *mtls.DynamicAuthorizer
	oauthValidator oauth.JWTValidator
	riskStore      *rbac.RiskStore
	tagStore       *rbac.TagStore
	caPolicyCache  *ca.PolicyCache
	mgmtAPIKey     string
	apiKeyHash     [32]byte
	startTime      time.Time
}

// NewServer creates a management API server bound to localhost:port.
func NewServer(port int, store *rbac.PolicyStore, logger *logging.AccessLogger, identity *spiffe.WorkloadIdentity, dynamicAuth *mtls.DynamicAuthorizer, oauthValidator oauth.JWTValidator, riskStore *rbac.RiskStore, tagStore *rbac.TagStore, opts ...ServerOption) *Server {
	s := &Server{
		store:          store,
		logger:         logger,
		identity:       identity,
		dynamicAuth:    dynamicAuth,
		oauthValidator: oauthValidator,
		riskStore:      riskStore,
		tagStore:       tagStore,
		startTime:      time.Now().UTC(),
	}
	for _, opt := range opts {
		opt(s)
	}

	s.mgmtAPIKey = os.Getenv("MGMT_API_KEY")
	if s.mgmtAPIKey == "" {
		log.Println("[MGMT] WARNING: MGMT_API_KEY not set — management API running without authentication")
	} else {
		s.apiKeyHash = sha256.Sum256([]byte(s.mgmtAPIKey))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/policy", s.handlePolicy)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/audit", s.handleAudit)
	mux.HandleFunc("/audit/stream", s.handleAuditStream)
	mux.HandleFunc("/mtls-policy", s.handleMTLSPolicy)
	mux.HandleFunc("/oauth-status", s.handleOAuthStatus)
	mux.HandleFunc("/agent-risk", s.handleAgentRisk)
	mux.HandleFunc("/agent-tags", s.handleAgentTags)
	mux.HandleFunc("/ca-policy-effective", s.handleCAPolicyEffective)

	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: s.authMiddleware(mux),
	}

	return s
}

// authMiddleware enforces shared-secret authentication via the X-AIM-Admin-Key
// header on all management endpoints except /health (which must remain open for
// liveness probes). When MGMT_API_KEY is unset the middleware is a no-op so
// existing deployments continue to work during migration.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health endpoint is always accessible (for liveness probes).
		// Also match trailing-slash form that ServeMux would normally redirect.
		if r.URL.Path == "/health" || r.URL.Path == "/health/" {
			next.ServeHTTP(w, r)
			return
		}
		if s.mgmtAPIKey != "" {
			providedKey := r.Header.Get("X-AIM-Admin-Key")
			actualHash := sha256.Sum256([]byte(providedKey))
			if subtle.ConstantTimeCompare(s.apiKeyHash[:], actualHash[:]) != 1 {
				jsonError(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Start begins serving in a goroutine.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("mgmt listen: %w", err)
	}
	log.Printf("[MGMT] Management API listening on %s", s.httpServer.Addr)
	go func() {
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[MGMT] Server error: %v", err)
		}
	}()
	return nil
}

// Stop gracefully shuts down the management API.
func (s *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.httpServer.Shutdown(ctx)
}

// ─── Handlers ───

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getPolicy(w, r)
	case http.MethodPut:
		s.putPolicy(w, r)
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	policy := s.store.Get()
	if policy == nil {
		http.Error(w, `{"error":"no_policy_loaded"}`, http.StatusNotFound)
		return
	}

	type policyResponse struct {
		*rbac.Policy
		LoadedAt     string `json:"loaded_at"`
		RequestCount int64  `json:"request_count"`
	}

	resp := policyResponse{
		Policy:       policy,
		LoadedAt:     s.store.LoadedAt().Format(time.RFC3339),
		RequestCount: s.logger.GetMetrics().TotalRequests,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) putPolicy(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64KB limit — mitigates YAML bomb DoS
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			json.NewEncoder(w).Encode(map[string]any{
				"error":     "payload_too_large",
				"max_bytes": 65536,
			})
		} else {
			jsonError(w, "failed to read body", http.StatusBadRequest)
		}
		return
	}

	oldVersion := s.store.Version()
	if err := s.store.LoadFromBytes(body); err != nil {
		jsonError(w, fmt.Sprintf("policy validation failed: %v", err), http.StatusBadRequest)
		return
	}
	// Re-enrich from env vars so hot-pushed policies with generic prefixes
	// get the real blueprint + agent OIDs (same as startup).
	s.store.EnrichFromEnv()

	newVersion := s.store.Version()
	log.Printf("[MGMT] Policy updated: %s → %s", oldVersion, newVersion)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":      "updated",
		"old_version": oldVersion,
		"new_version": newVersion,
		"loaded_at":   s.store.LoadedAt().Format(time.RFC3339),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	health := map[string]interface{}{
		"status":           "healthy",
		"policy_version":   s.store.Version(),
		"policy_loaded_at": s.store.LoadedAt().Format(time.RFC3339),
		"uptime_seconds":   int(time.Since(s.startTime).Seconds()),
	}

	// SVID info if identity is available.
	if s.identity != nil {
		cert, err := s.identity.GetSVID()
		if err == nil {
			health["spire_agent_connected"] = true
			health["svid_expiry"] = cert.NotAfter.Format(time.RFC3339)
			health["svid_ttl_seconds"] = int(time.Until(cert.NotAfter).Seconds())
		} else {
			health["spire_agent_connected"] = false
			health["svid_error"] = err.Error()
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.logger.GetMetrics())
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}

	spiffeIDFilter := r.URL.Query().Get("spiffe_id")
	decisionFilter := r.URL.Query().Get("decision")

	entries := s.logger.Recent(limit, spiffeIDFilter, decisionFilter)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":   len(entries),
		"entries": entries,
	})
}

// handleAuditStream streams new AccessEntry events to the client as
// Server-Sent Events. Clients reconnect via EventSource on drop.
// Auth is already enforced by authMiddleware.
func (s *Server) handleAuditStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method_not_allowed", http.StatusMethodNotAllowed)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		jsonError(w, "streaming_unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Initial comment flushes headers and keeps intermediaries happy.
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ch, cancel := s.logger.Subscribe()
	defer cancel()

	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case entry := <-ch:
			// Subscription channel is never closed by the logger; we only
			// exit via r.Context().Done() (client disconnect) or write errors.
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// ─── mTLS Policy Handler ───

func (s *Server) handleMTLSPolicy(w http.ResponseWriter, r *http.Request) {
	if s.dynamicAuth == nil {
		jsonError(w, "dynamic mTLS authorizer not configured", http.StatusNotImplemented)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getMTLSPolicy(w, r)
	case http.MethodPut:
		s.putMTLSPolicy(w, r)
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) getMTLSPolicy(w http.ResponseWriter, r *http.Request) {
	ids := s.dynamicAuth.List()
	idStrings := make([]string, len(ids))
	for i, id := range ids {
		idStrings[i] = id.String()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"mode":        "allowlist",
		"allowed_ids": idStrings,
		"count":       len(idStrings),
	})
}

func (s *Server) putMTLSPolicy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		jsonError(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var req struct {
		AllowedIDs []string `json:"allowed_ids"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		jsonError(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Get old list for response.
	oldIDs := s.dynamicAuth.List()
	oldStrings := make([]string, len(oldIDs))
	for i, id := range oldIDs {
		oldStrings[i] = id.String()
	}

	// Validate and parse new SPIFFE IDs.
	var newIDs []spiffeid.ID
	for _, idStr := range req.AllowedIDs {
		idStr = strings.TrimSpace(idStr)
		if idStr == "" {
			continue
		}
		id, err := spiffeid.FromString(idStr)
		if err != nil {
			jsonError(w, fmt.Sprintf("invalid SPIFFE ID %q: %v", idStr, err), http.StatusBadRequest)
			return
		}
		newIDs = append(newIDs, id)
	}

	// Reject empty allow list unless explicitly forced — an empty list
	// locks out all callers and there is no self-service recovery path.
	if len(newIDs) == 0 && r.URL.Query().Get("force") != "true" {
		jsonError(w, "empty allow list would lock out all callers. Use ?force=true to override.", http.StatusBadRequest)
		return
	}

	// Atomic update.
	s.dynamicAuth.Update(newIDs)

	newStrings := make([]string, len(newIDs))
	for i, id := range newIDs {
		newStrings[i] = id.String()
	}

	log.Printf("[MGMT] mTLS allow list updated: %d → %d identities", len(oldIDs), len(newIDs))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "updated",
		"old_allowed_ids": oldStrings,
		"new_allowed_ids": newStrings,
		"old_count":       len(oldStrings),
		"new_count":       len(newStrings),
	})
}

// ─── OAuth Status Handler ───

func (s *Server) handleOAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method_not_allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.oauthValidator == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"config_loaded": false,
			"message":       "OAuth/JWT enforcement not configured (no oauth-config.yaml)",
		})
		return
	}

	status := s.oauthValidator.Status()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// ─── Agent Risk Handler (Layer 4b — CA data-plane) ───

func (s *Server) handleAgentRisk(w http.ResponseWriter, r *http.Request) {
	if s.riskStore == nil {
		jsonError(w, "risk store not configured", http.StatusNotImplemented)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getAgentRisk(w, r)
	case http.MethodPut:
		s.putAgentRisk(w, r)
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) getAgentRisk(w http.ResponseWriter, r *http.Request) {
	// If ?spiffe_id= is provided, return risk for that specific agent.
	if spiffeID := r.URL.Query().Get("spiffe_id"); spiffeID != "" {
		risk := s.riskStore.GetRisk(spiffeID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"spiffe_id":  spiffeID,
			"risk_level": risk,
		})
		return
	}

	// Otherwise return all risk levels.
	risks := s.riskStore.GetAll()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"risks":         risks,
		"count":         len(risks),
		"default_level": "low",
	})
}

func (s *Server) putAgentRisk(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		jsonError(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var req struct {
		SpiffeID  string `json:"spiffe_id"`
		RiskLevel string `json:"risk_level"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		jsonError(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	if req.SpiffeID == "" {
		jsonError(w, "spiffe_id is required", http.StatusBadRequest)
		return
	}
	if !rbac.ValidRiskLevel(req.RiskLevel) {
		jsonError(w, fmt.Sprintf("invalid risk_level %q: must be low, medium, or high", req.RiskLevel), http.StatusBadRequest)
		return
	}

	previousLevel := s.riskStore.SetRisk(req.SpiffeID, req.RiskLevel)

	log.Printf("[MGMT] Agent risk updated: %s → %s (was %s)", req.SpiffeID, req.RiskLevel, previousLevel)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "updated",
		"spiffe_id":      req.SpiffeID,
		"risk_level":     req.RiskLevel,
		"previous_level": previousLevel,
	})
}

// ─── Agent Tags Handler (Layer 4b — CA custom security attributes) ───

func (s *Server) handleAgentTags(w http.ResponseWriter, r *http.Request) {
	if s.tagStore == nil {
		jsonError(w, "tag store not configured", http.StatusNotImplemented)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getAgentTags(w, r)
	case http.MethodPut:
		s.putAgentTag(w, r)
	default:
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) getAgentTags(w http.ResponseWriter, r *http.Request) {
	// If ?spiffe_id= is provided, return tag for that specific agent.
	if spiffeID := r.URL.Query().Get("spiffe_id"); spiffeID != "" {
		tag, ok := s.tagStore.GetTag(spiffeID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"spiffe_id": spiffeID,
			"tag":       tag,
			"source":    "graph",
			"found":     ok,
		})
		return
	}

	// Otherwise return all tags.
	tags := s.tagStore.GetAll()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tags":   tags,
		"count":  len(tags),
		"source": "graph",
	})
}

func (s *Server) putAgentTag(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		jsonError(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var req struct {
		SpiffeID string `json:"spiffe_id"`
		Tag      string `json:"tag"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		jsonError(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	if req.SpiffeID == "" {
		jsonError(w, "spiffe_id is required", http.StatusBadRequest)
		return
	}

	previousTag := s.tagStore.SetTag(req.SpiffeID, req.Tag)

	log.Printf("[MGMT] Agent tag updated: %s → %q (was %q)", req.SpiffeID, req.Tag, previousTag)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "updated",
		"spiffe_id":    req.SpiffeID,
		"tag":          req.Tag,
		"previous_tag": previousTag,
		"source":       "graph",
	})
}

func jsonError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ServerOption configures optional Server components.
type ServerOption func(*Server)

// WithCAPolicyCache sets the CA policy cache for the management API.
func WithCAPolicyCache(cache *ca.PolicyCache) ServerOption {
	return func(s *Server) {
		s.caPolicyCache = cache
	}
}

// handleCAPolicyEffective returns the effective CA policy state from the Graph-synced cache.
// This is the source of truth for what risk levels are being blocked.
func (s *Server) handleCAPolicyEffective(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	result := map[string]interface{}{
		"source": "ca_policy_cache",
	}

	if s.caPolicyCache == nil {
		result["enabled"] = false
		result["blocked_risk_levels"] = []string{}
		result["reason"] = "CA policy cache not configured (GRAPH_CLIENT_ID/SECRET not set)"
	} else {
		status := s.caPolicyCache.Status()
		result["enabled"] = status["enabled"]
		result["blocked_risk_levels"] = status["blocked_risk_levels"]
		result["policy_count"] = status["policy_count"]
		result["fetch_count"] = status["fetch_count"]
		result["sync_interval"] = status["sync_interval"]
		if v, ok := status["last_fetch"]; ok {
			result["last_fetch"] = v
		}
		if v, ok := status["age_seconds"]; ok {
			result["age_seconds"] = v
		}
		if v, ok := status["last_error"]; ok {
			result["last_error"] = v
		}
		// Include individual cached policies for debugging
		result["policies"] = s.caPolicyCache.GetCachedPolicies()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
