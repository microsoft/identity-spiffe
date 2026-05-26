// Package main implements a unified SPIFFE-authenticated proxy for the AIM Prototype Platform.
//
// It runs in two modes controlled by the PROXY_MODE environment variable:
//
//   - egress:  Listens for plain HTTP from the local agent, tunnels it over
//     gRPC+mTLS to the remote ingress proxy. Runs alongside caller agents (A1, A3, A4).
//
//   - ingress: Listens for gRPC+mTLS connections from egress proxies, validates
//     caller SPIFFE IDs, and forwards traffic as plain HTTP to the local app.
//     Runs alongside the resource agent (A2).
//
// Both modes obtain their SPIFFE identity from the local SPIRE Agent via the
// Workload API (Unix Domain Socket).
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/project-aim/spiffe-proxy/internal/ca"
	"github.com/project-aim/spiffe-proxy/internal/gateway"
	"github.com/project-aim/spiffe-proxy/internal/logging"
	"github.com/project-aim/spiffe-proxy/internal/mgmt"
	aimtls "github.com/project-aim/spiffe-proxy/internal/mtls"
	"github.com/project-aim/spiffe-proxy/internal/oauth"
	"github.com/project-aim/spiffe-proxy/internal/rbac"
	"github.com/project-aim/spiffe-proxy/internal/spiffe"
	"github.com/project-aim/spiffe-proxy/internal/tunnel"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	mode := getEnv("PROXY_MODE", "egress")
	spireSocket := getEnv("SPIRE_SOCKET_PATH", "/opt/spire/sockets/workload.sock")

	log.Println("========================================")
	log.Printf("  AIM Prototype Platform - SPIFFE Proxy (%s)", strings.ToUpper(mode))
	log.Println("========================================")

	switch mode {
	case "egress":
		runEgress(spireSocket)
	case "ingress":
		runIngress(spireSocket)
	default:
		log.Fatalf("Unknown PROXY_MODE: %s (must be 'egress' or 'ingress')", mode)
	}
}

// lazyTunnel manages a tunnel connection that may not exist at startup.
// This enables the "deploy blocked → add to allow list → works" demo flow.
// Without this, the egress proxy crashes if the ingress rejects the initial
// TLS handshake (agent not in allow list), and never recovers.
type lazyTunnel struct {
	mu         sync.Mutex
	client     *tunnel.Client
	remoteAddr string
	tlsConfig  *tls.Config
}

func (lt *lazyTunnel) tryConnect() bool {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if lt.client != nil {
		return true
	}
	client, err := tunnel.NewClient(lt.remoteAddr, lt.tlsConfig)
	if err != nil {
		log.Printf("[Egress] Tunnel connect failed: %v", err)
		return false
	}
	lt.client = client
	log.Println("[Egress] ✓ gRPC mTLS tunnel established!")
	return true
}

func (lt *lazyTunnel) get() *tunnel.Client {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return lt.client
}

func (lt *lazyTunnel) reset() {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if lt.client != nil {
		lt.client.Close()
		lt.client = nil
		log.Println("[Egress] Tunnel connection reset (will retry)")
	}
}

func (lt *lazyTunnel) close() {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if lt.client != nil {
		lt.client.Close()
		lt.client = nil
	}
}

// reconnectLoop retries the tunnel connection every 2m while disconnected.
// On-demand tryConnect() in the request path handles immediate retries;
// this loop is a background fallback for broken connections.
func (lt *lazyTunnel) reconnectLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Minute):
		}
		if lt.get() != nil {
			continue // already connected
		}
		lt.tryConnect()
	}
}

func runEgress(spireSocket string) {
	httpListenAddr := getEnv("HTTP_LISTEN_ADDR", ":8080")
	remoteProxyAddr := getEnv("REMOTE_PROXY_ADDR", "a2-resource-ingress:8443")
	allowedRemoteID := getEnv("ALLOWED_REMOTE_SPIFFE_ID", "spiffe://aim.microsoft.com/ests/bp/default/aid/a2-resource")

	log.Printf("HTTP Listen: %s", httpListenAddr)
	log.Printf("Remote Proxy: %s", remoteProxyAddr)
	log.Printf("SPIRE Socket: %s", spireSocket)
	log.Printf("Allowed Remote ID: %s", allowedRemoteID)
	log.Println("========================================")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	identity := connectToSpire(ctx, spireSocket)
	defer identity.Close()

	allowedID, err := spiffeid.FromString(allowedRemoteID)
	if err != nil {
		log.Fatalf("[Egress] Invalid allowed SPIFFE ID: %v", err)
	}

	tlsConfig := identity.GetClientTLSConfig([]spiffeid.ID{allowedID})

	// Start HTTP listener FIRST so the agent's FastAPI can always reach :8080.
	// Without this, blocked agents crash before the listener starts.
	httpListener, err := net.Listen("tcp", httpListenAddr)
	if err != nil {
		log.Fatalf("[Egress] Failed to listen on %s: %v", httpListenAddr, err)
	}
	defer httpListener.Close()
	log.Printf("[Egress] ✓ HTTP listener ready on %s", httpListenAddr)

	// Lazy tunnel: try to connect but don't crash if blocked.
	lt := &lazyTunnel{remoteAddr: remoteProxyAddr, tlsConfig: tlsConfig}
	defer lt.close()

	log.Printf("[Egress] Connecting to %s...", remoteProxyAddr)
	if lt.tryConnect() {
		log.Println("[Egress] ✓ Agent can send plain HTTP to localhost:8080")
	} else {
		log.Println("[Egress] ⚠ Tunnel not available — agent may not be in the mTLS allow list yet")
		log.Println("[Egress]   Retrying in background every 2m (plus immediate on-demand retries). Requests return 502 until connected.")
	}
	log.Println("========================================")

	// Background reconnection
	go lt.reconnectLoop(ctx)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
		httpListener.Close()
	}()

	for {
		conn, err := httpListener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[Egress] Accept error: %v", err)
				continue
			}
		}
		connectionID := uuid.New().String()[:8]
		log.Printf("[Egress] New connection from %s (id: %s)", conn.RemoteAddr(), connectionID)
		go func(c net.Conn, id string) {
			defer c.Close()

			client := lt.get()
			if client == nil {
				// On-demand retry (allow list may have just been updated)
				lt.tryConnect()
				client = lt.get()
			}
			if client == nil {
				log.Printf("[Egress] Connection %s: tunnel unavailable, returning 502", id)
				c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n" +
					`{"error":"mTLS tunnel not connected. This agent is not yet in the backend allow list. Add it via the mTLS tab and retry.","http_status":502}` + "\r\n"))
				return
			}
			if err := client.ForwardConnection(ctx, c, id); err != nil {
				log.Printf("[Egress] Connection %s error: %v", id, err)
				// Connection may be broken — reset so next request retries
				lt.reset()
			}
		}(conn, connectionID)
	}
}

func runIngress(spireSocket string) {
	grpcListenAddr := getEnv("GRPC_LISTEN_ADDR", ":8443")
	appAddr := getEnv("APP_ADDR", "localhost:8000")
	allowedCallerIDs := getEnv("ALLOWED_CALLER_SPIFFE_IDS", "")
	policyPath := getEnv("RBAC_POLICY_PATH", "")
	oauthConfigPath := getEnv("OAUTH_CONFIG_PATH", "/opt/spiffe-proxy/config/oauth-config.yaml")
	mgmtPort := getEnv("MGMT_API_PORT", "9443")

	log.Printf("gRPC Listen: %s", grpcListenAddr)
	log.Printf("App Address: %s", appAddr)
	log.Printf("SPIRE Socket: %s", spireSocket)
	log.Printf("Allowed Caller IDs: %s", allowedCallerIDs)
	if policyPath != "" {
		log.Printf("RBAC Policy: %s", policyPath)
	} else {
		log.Println("RBAC Policy: disabled (no RBAC_POLICY_PATH set)")
	}
	log.Println("========================================")

	if allowedCallerIDs == "" {
		log.Fatal("[Ingress] ALLOWED_CALLER_SPIFFE_IDS must be set (comma-separated SPIFFE IDs)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	identity := connectToSpire(ctx, spireSocket)
	defer identity.Close()

	// Parse comma-separated allowed caller SPIFFE IDs
	var allowedIDs []spiffeid.ID
	for _, idStr := range strings.Split(allowedCallerIDs, ",") {
		idStr = strings.TrimSpace(idStr)
		if idStr == "" {
			continue
		}
		id, err := spiffeid.FromString(idStr)
		if err != nil {
			log.Fatalf("[Ingress] Invalid allowed SPIFFE ID '%s': %v", idStr, err)
		}
		allowedIDs = append(allowedIDs, id)
		log.Printf("[Ingress] ✓ Allowing caller: %s", idStr)
	}

	// ─── Gateway RBAC Extension ───
	// Initialize RBAC engine, access logger, and management API if a policy path is set.
	accessLogger := logging.NewAccessLogger(1000)
	policyStore := rbac.NewPolicyStore()

	// Create dynamic mTLS authorizer — allow list can be modified at runtime via mgmt API.
	// The onReject callback feeds mTLS rejections into the access logger.
	dynamicAuth := aimtls.NewDynamicAuthorizer(allowedIDs, func(callerSpiffeID string) {
		accessLogger.LogMTLSRejection(callerSpiffeID)
	})

	// Use dynamic TLS config instead of static AuthorizeOneOf.
	tlsConfig := identity.GetDynamicServerTLSConfig(dynamicAuth)
	tunnelServer := tunnel.NewServer(appAddr, tlsConfig, identity.SpiffeID().String())

	// Enable per-stream re-validation so mTLS policy changes take effect
	// immediately on existing connections (not just new TLS handshakes).
	tunnelServer.SetDynamicAuth(dynamicAuth)

	// ─── Layer 3: OAuth/JWT Validator ───
	// Load OAuth config for JWT validation. If the config file is absent or
	// incomplete, the proxy still starts, but require_jwt rules fail closed
	// until a validator becomes available.
	var oauthValidator oauth.JWTValidator
	oauthCfg, err := oauth.LoadConfig(oauthConfigPath)
	if err != nil {
		log.Printf("[Ingress] OAuth config not loaded (%v) — require_jwt routes will deny", err)
	} else if oauthCfg.TenantID == "" || oauthCfg.Audience == "" {
		log.Println("[Ingress] OAuth config incomplete (missing tenant_id or audience) — require_jwt routes will deny")
	} else {
		oauthValidator = oauth.NewValidator(oauthCfg)
		log.Printf("[Ingress] ✓ OAuth/JWT enforcement enabled (tenant: %s, audience: %s)", oauthCfg.TenantID, oauthCfg.Audience)
	}

	// Create risk store for Layer 4b (data-plane CA) enforcement.
	// Created before policy loading so they're accessible by both the RBAC engine
	// and the management API (for /agent-risk and /agent-tags endpoints).
	riskStore := rbac.NewRiskStore()
	tagStore := rbac.NewTagStore()

	// CA policy cache — declared at function scope so mgmt API can access it
	var policyCache *ca.PolicyCache

	if policyPath != "" {
		if err := policyStore.LoadFromFile(policyPath); err != nil {
			log.Fatalf("[Ingress] Failed to load RBAC policy from %s: %v", policyPath, err)
		}
		// Enrich policy entries with Entra Agent IDs from env vars.
		// This replaces placeholder values baked into the YAML with real IDs
		// injected by deploy.sh at container startup time.
		policyStore.EnrichFromEnv()

		// Validate that no two CallerPolicy entries share the same prefix after
		// enrichment. Duplicate prefixes cause first-match-wins ambiguity where
		// the second policy is silently unreachable (issue #56).
		if err := policyStore.Get().ValidateNoDuplicatePrefixes(); err != nil {
			log.Fatalf("[Ingress] RBAC policy prefix collision: %v", err)
		}

		log.Printf("[Ingress] ✓ RBAC policy loaded: version=%s, %d caller policies",
			policyStore.Version(), len(policyStore.Get().Policies))

		// Create RBAC engine (with optional OAuth validator, risk store, and tag store)
		// and gateway interceptor. TagStore enables real Entra custom security
		// attributes to override YAML ca.agent_tag values at runtime.
		// CA policy cache enables Graph-sourced blocked risk levels from Entra CA policies.
		var engineOpts []rbac.EngineOption
		graphClient := ca.NewGraphClient(
			os.Getenv("AZURE_TENANT_ID"),
			os.Getenv("GRAPH_CLIENT_ID"),
			os.Getenv("GRAPH_CLIENT_SECRET"),
		)
		if graphClient != nil {
			syncSec := 60
			if v := os.Getenv("CA_POLICY_SYNC_INTERVAL"); v != "" {
				if s, err := strconv.Atoi(v); err == nil && s > 0 {
					syncSec = s
				}
			}
			policyCache = ca.NewPolicyCache(graphClient, time.Duration(syncSec)*time.Second)
			policyCache.Start()
			defer policyCache.Stop()
			engineOpts = append(engineOpts, rbac.WithCAPolicyCache(policyCache))
			log.Printf("[Ingress] ✓ CA policy cache enabled (sync every %ds)", syncSec)
		} else {
			log.Printf("[Ingress] CA policy cache disabled (GRAPH_CLIENT_ID/SECRET not set)")
		}
		engine := rbac.NewEngine(policyStore, oauthValidator, riskStore, tagStore, engineOpts...)
		interceptor := gateway.NewInterceptor(engine, accessLogger)
		tunnelServer.SetInterceptor(interceptor)
	}

	// Start management API (always, so mTLS policy is accessible even without RBAC).
	port := 9443
	if v := mgmtPort; v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			port = p
		}
	}
	var mgmtOpts []mgmt.ServerOption
	if policyCache != nil {
		mgmtOpts = append(mgmtOpts, mgmt.WithCAPolicyCache(policyCache))
	}
	mgmtServer := mgmt.NewServer(port, policyStore, accessLogger, identity, dynamicAuth, oauthValidator, riskStore, tagStore, mgmtOpts...)
	if err := mgmtServer.Start(); err != nil {
		log.Printf("[Ingress] Warning: management API failed to start: %v", err)
	} else {
		log.Printf("[Ingress] ✓ Management API listening on 127.0.0.1:%d", port)
	}
	defer mgmtServer.Stop()

	grpcListener, err := net.Listen("tcp", grpcListenAddr)
	if err != nil {
		log.Fatalf("[Ingress] Failed to listen on %s: %v", grpcListenAddr, err)
	}
	defer grpcListener.Close()

	log.Printf("[Ingress] ✓ gRPC mTLS listener ready on %s", grpcListenAddr)
	log.Printf("[Ingress] ✓ Forwarding to app at %s", appAddr)
	log.Println("========================================")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
		tunnelServer.Stop()
	}()

	if err := tunnelServer.Serve(grpcListener); err != nil {
		select {
		case <-ctx.Done():
			log.Println("[Ingress] Server stopped gracefully")
		default:
			log.Printf("[Ingress] Server error: %v", err)
		}
	}
}

func connectToSpire(ctx context.Context, socketPath string) *spiffe.WorkloadIdentity {
	log.Println("[SPIFFE] Connecting to SPIRE agent...")
	var identity *spiffe.WorkloadIdentity
	var err error
	for i := 0; i < 30; i++ {
		identity, err = spiffe.NewWorkloadIdentity(ctx, socketPath)
		if err == nil {
			break
		}
		log.Printf("[SPIFFE] Waiting for SPIRE agent... (%d/30): %v", i+1, err)
		select {
		case <-ctx.Done():
			log.Fatalf("[SPIFFE] Context cancelled while waiting for SPIRE: %v", ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
	if err != nil {
		log.Fatalf("[SPIFFE] Failed to create workload identity after 60s: %v", err)
	}
	log.Printf("[SPIFFE] ✓ Got SPIFFE ID: %s", identity.SpiffeID())
	return identity
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
