package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/project-aim/spiffe-proxy/internal/gateway"
	aimtls "github.com/project-aim/spiffe-proxy/internal/mtls"
	"github.com/project-aim/spiffe-proxy/internal/tunnel/tunnelpb"
)

// Server handles incoming gRPC tunnel connections and forwards to the local app.
type Server struct {
	tunnelpb.UnimplementedTunnelServiceServer

	grpcServer     *grpc.Server
	appAddr        string
	spiffeID       string
	connections    map[string]net.Conn
	mu             sync.RWMutex
	maxConnections int                       // max concurrent tunnel connections
	interceptor    *gateway.Interceptor      // nil = passthrough (no RBAC)
	dynamicAuth    *aimtls.DynamicAuthorizer // nil = no per-stream re-auth
}

// NewServer creates a new tunnel server with mTLS.
func NewServer(appAddr string, tlsConfig *tls.Config, spiffeID string) *Server {
	creds := credentials.NewTLS(tlsConfig)

	kaParams := keepalive.ServerParameters{
		MaxConnectionIdle:     30 * time.Second,
		MaxConnectionAge:      5 * time.Minute,
		MaxConnectionAgeGrace: 5 * time.Second,
		Time:                  10 * time.Second,
		Timeout:               3 * time.Second,
	}

	kaPolicy := keepalive.EnforcementPolicy{
		MinTime:             5 * time.Second,
		PermitWithoutStream: true,
	}

	server := &Server{
		appAddr:        appAddr,
		spiffeID:       spiffeID,
		connections:    make(map[string]net.Conn),
		maxConnections: 100,
	}

	server.grpcServer = grpc.NewServer(
		grpc.Creds(creds),
		grpc.KeepaliveParams(kaParams),
		grpc.KeepaliveEnforcementPolicy(kaPolicy),
		grpc.StreamInterceptor(server.streamAuthInterceptor),
		grpc.UnaryInterceptor(server.unaryAuthInterceptor),
		grpc.MaxRecvMsgSize(64*1024), // 64KB max message size (DoS protection)
	)

	tunnelpb.RegisterTunnelServiceServer(server.grpcServer, server)
	return server
}

// SetInterceptor enables gateway RBAC interception on this server.
// When set, the first DATA payload in each tunnel is inspected, RBAC-evaluated,
// and either forwarded with injected headers or rejected with HTTP 403.
func (s *Server) SetInterceptor(i *gateway.Interceptor) {
	s.interceptor = i
	log.Println("[Tunnel Server] ✓ Gateway RBAC interceptor enabled")
}

// SetDynamicAuth enables per-stream re-validation of the caller's SPIFFE ID
// against the dynamic mTLS allow list. This ensures that allow list changes
// take effect immediately — even on existing gRPC connections whose TLS
// handshake was authorized before the policy change.
func (s *Server) SetDynamicAuth(auth *aimtls.DynamicAuthorizer) {
	s.dynamicAuth = auth
	log.Println("[Tunnel Server] ✓ Per-stream mTLS re-validation enabled")
}

func (s *Server) unaryAuthInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	peerID, err := s.extractPeerSpiffeID(ctx)
	if err != nil {
		log.Printf("[Tunnel Server] ❌ AUTH FAILED: %v", err)
		return nil, status.Errorf(codes.PermissionDenied, "authentication failed: %v", err)
	}
	log.Printf("[Tunnel Server] ✓ Authenticated peer: %s", peerID)
	return handler(ctx, req)
}

func (s *Server) streamAuthInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	peerID, err := s.extractPeerSpiffeID(ss.Context())
	if err != nil {
		log.Printf("[Tunnel Server] ❌ AUTH FAILED: %v", err)
		return status.Errorf(codes.PermissionDenied, "authentication failed: %v", err)
	}

	// Re-validate against the current dynamic allow list on every stream.
	// The TLS handshake authorized this connection at establishment time, but
	// the allow list may have changed since then. This ensures policy changes
	// take effect immediately without waiting for connection turnover.
	if s.dynamicAuth != nil {
		id, parseErr := spiffeid.FromString(peerID)
		if parseErr != nil {
			log.Printf("[Tunnel Server] ❌ STREAM REJECTED: invalid SPIFFE ID %q: %v", peerID, parseErr)
			return status.Errorf(codes.PermissionDenied, "invalid SPIFFE ID: %v", parseErr)
		}
		if authErr := s.dynamicAuth.Authorize(id); authErr != nil {
			log.Printf("[Tunnel Server] ❌ STREAM REJECTED: %s removed from allow list", peerID)
			return status.Errorf(codes.PermissionDenied, "mTLS policy changed: %v", authErr)
		}
	}

	log.Printf("[Tunnel Server] ✓ Authenticated stream from: %s", peerID)
	return handler(srv, ss)
}

// extractPeerSpiffeID extracts and returns the SPIFFE ID from the peer's mTLS certificate.
// The actual allow/deny decision is handled by the go-spiffe TLS authorizer configured
// in the TLS config — if we get here, the peer was already authorized.
func (s *Server) extractPeerSpiffeID(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", fmt.Errorf("no peer information")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", fmt.Errorf("no TLS info - mTLS required")
	}
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return "", fmt.Errorf("no peer certificates")
	}
	cert := tlsInfo.State.PeerCertificates[0]
	for _, uri := range cert.URIs {
		return uri.String(), nil
	}
	return "", fmt.Errorf("no SPIFFE URI SAN in peer certificate")
}

// HealthCheck returns the server's health status and SPIFFE ID.
func (s *Server) HealthCheck(ctx context.Context, req *tunnelpb.HealthCheckRequest) (*tunnelpb.HealthCheckResponse, error) {
	return &tunnelpb.HealthCheckResponse{
		Healthy:  true,
		SpiffeId: s.spiffeID,
		Version:  "1.0.0-aim",
	}, nil
}

// Tunnel handles bidirectional tunneling — receives from gRPC, forwards as HTTP to local app.
//
// When a gateway interceptor is set:
//   - The first DATA payload is inspected: HTTP method/path is extracted and RBAC-evaluated
//   - If allowed: caller context headers are injected and the modified request is forwarded
//   - If denied: HTTP 403 is sent back through the tunnel; the app never sees the request
//   - SECURITY: Only one HTTP request is permitted per tunnel connection when RBAC is active.
//     After the first request is forwarded, subsequent DATA payloads are rejected and the
//     tunnel is closed. This prevents HTTP pipelining/smuggling bypasses where a second
//     request could skip RBAC evaluation.
func (s *Server) Tunnel(stream tunnelpb.TunnelService_TunnelServer) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	if msg.Type != tunnelpb.MessageType_MESSAGE_TYPE_CONNECT {
		return fmt.Errorf("expected CONNECT message, got %v", msg.Type)
	}

	connectionID := msg.ConnectionId

	// DoS protection: reject oversized connectionIDs to prevent memory abuse.
	if len(connectionID) > 64 {
		return status.Errorf(codes.InvalidArgument, "connectionID exceeds 64 byte limit")
	}

	if connectionID == "" {
		return status.Errorf(codes.InvalidArgument, "connectionID must not be empty")
	}

	// DoS protection: atomically reserve a slot so the concurrent connection
	// limit is enforced strictly under concurrency.
	s.mu.Lock()
	if _, exists := s.connections[connectionID]; exists {
		s.mu.Unlock()
		return status.Errorf(codes.AlreadyExists, "connectionID %q is already in use", connectionID)
	}
	if len(s.connections) >= s.maxConnections {
		s.mu.Unlock()
		return status.Errorf(codes.ResourceExhausted, "max concurrent connections (%d) exceeded", s.maxConnections)
	}
	s.connections[connectionID] = nil
	s.mu.Unlock()

	reserved := true
	defer func() {
		if reserved {
			s.mu.Lock()
			delete(s.connections, connectionID)
			s.mu.Unlock()
		}
	}()

	// Extract the caller's SPIFFE ID from the mTLS peer certificate.
	callerSpiffeID, extractErr := s.extractPeerSpiffeID(stream.Context())
	if extractErr != nil {
		log.Printf("[Tunnel Server] Connection %s: failed to extract SPIFFE ID: %v", connectionID, extractErr)
		return fmt.Errorf("failed to extract caller SPIFFE ID: %w", extractErr)
	}

	log.Printf("[Tunnel Server] New tunnel connection: %s (from: %s, caller: %s)",
		connectionID, msg.Metadata["remote_addr"], callerSpiffeID)

	appConn, err := net.DialTimeout("tcp", s.appAddr, 5*time.Second)
	if err != nil {
		errMsg := fmt.Sprintf("failed to connect to local app: %v", err)
		log.Printf("[Tunnel Server] Connection %s: %s", connectionID, errMsg)
		stream.Send(&tunnelpb.TunnelMessage{
			ConnectionId: connectionID,
			Type:         tunnelpb.MessageType_MESSAGE_TYPE_ERROR,
			Payload:      []byte(errMsg),
		})
		return err
	}
	defer appConn.Close()

	// DoS protection: enforce a hard deadline so tunnels cannot be held open indefinitely.
	if err := appConn.SetDeadline(time.Now().Add(5 * time.Minute)); err != nil {
		errMsg := fmt.Sprintf("failed to set deadline on local app connection: %v", err)
		log.Printf("[Tunnel Server] Connection %s: %s", connectionID, errMsg)
		stream.Send(&tunnelpb.TunnelMessage{
			ConnectionId: connectionID,
			Type:         tunnelpb.MessageType_MESSAGE_TYPE_ERROR,
			Payload:      []byte(errMsg),
		})
		return err
	}

	log.Printf("[Tunnel Server] Connection %s: forwarding to app at %s", connectionID, s.appAddr)

	s.mu.Lock()
	s.connections[connectionID] = appConn
	s.mu.Unlock()
	reserved = false
	defer func() {
		s.mu.Lock()
		delete(s.connections, connectionID)
		s.mu.Unlock()
	}()

	// Use a cancellable context so we can signal both goroutines to stop
	// when the first one finishes, preventing goroutine leaks.
	copyCtx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	errCh := make(chan error, 2)

	// App response → gRPC tunnel → caller
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := appConn.Read(buf)
			if err != nil {
				if err == io.EOF {
					errCh <- nil
				} else {
					// Suppress noisy errors when we cancelled the context ourselves.
					select {
					case <-copyCtx.Done():
						errCh <- nil
					default:
						errCh <- fmt.Errorf("app read error: %w", err)
					}
				}
				return
			}
			// Check if cancelled before sending on the stream to avoid
			// "send on closed stream" panics.
			select {
			case <-copyCtx.Done():
				errCh <- nil
				return
			default:
			}
			if err := stream.Send(&tunnelpb.TunnelMessage{
				ConnectionId: connectionID,
				Type:         tunnelpb.MessageType_MESSAGE_TYPE_DATA,
				Payload:      buf[:n],
			}); err != nil {
				errCh <- fmt.Errorf("tunnel send error: %w", err)
				return
			}
		}
	}()

	// gRPC tunnel (from caller) → App (with gateway interception on first payload)
	go func() {
		firstPayload := true
		rbacActive := s.interceptor != nil
		var remainingBodyBytes int64 // body bytes still expected after first payload
		for {
			msg, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					errCh <- nil
				} else {
					// Suppress noisy errors when we cancelled the context ourselves.
					select {
					case <-copyCtx.Done():
						errCh <- nil
					default:
						errCh <- fmt.Errorf("tunnel recv error: %w", err)
					}
				}
				return
			}
			switch msg.Type {
			case tunnelpb.MessageType_MESSAGE_TYPE_DATA:
				payload := msg.Payload

				// Gateway interception: evaluate RBAC on first DATA payload.
				if firstPayload && rbacActive {
					firstPayload = false
					result := s.interceptor.Process(callerSpiffeID, payload)

					if !result.Allowed {
						// Send HTTP 403 back through the tunnel.
						if sendErr := stream.Send(&tunnelpb.TunnelMessage{
							ConnectionId: connectionID,
							Type:         tunnelpb.MessageType_MESSAGE_TYPE_DATA,
							Payload:      result.DenyResponse,
						}); sendErr != nil {
							log.Printf("[Tunnel Server] Connection %s: failed to send 403 deny response: %v", connectionID, sendErr)
						}
						// Close the tunnel gracefully.
						if sendErr := stream.Send(&tunnelpb.TunnelMessage{
							ConnectionId: connectionID,
							Type:         tunnelpb.MessageType_MESSAGE_TYPE_DISCONNECT,
						}); sendErr != nil {
							log.Printf("[Tunnel Server] Connection %s: failed to send disconnect after deny: %v", connectionID, sendErr)
						}
						errCh <- nil
						return
					}
					// Use the modified payload (with injected headers).
					payload = result.ModifiedPayload
					remainingBodyBytes = result.RemainingBodyBytes
				} else if !firstPayload && rbacActive {
					// SECURITY: Allow continuation of request body (e.g., PUT/POST),
					// but reject additional data once the full body has been received.
					// This prevents HTTP pipelining/smuggling attacks where a second
					// request could skip RBAC evaluation, while still allowing
					// legitimate request bodies that span multiple tunnel messages.
					if remainingBodyBytes <= 0 {
						log.Printf("[Tunnel Server] Connection %s: REJECTED additional DATA payload after body complete (anti-smuggling). Closing tunnel.", connectionID)
						stream.Send(&tunnelpb.TunnelMessage{
							ConnectionId: connectionID,
							Type:         tunnelpb.MessageType_MESSAGE_TYPE_DISCONNECT,
						})
						errCh <- nil
						return
					}
					remainingBodyBytes -= int64(len(payload))
					log.Printf("[Tunnel Server] Connection %s: body continuation (%d bytes, %d remaining)", connectionID, len(payload), remainingBodyBytes)
				} else if firstPayload {
					firstPayload = false
				}

				if _, err := appConn.Write(payload); err != nil {
					errCh <- fmt.Errorf("app write error: %w", err)
					return
				}
			case tunnelpb.MessageType_MESSAGE_TYPE_DISCONNECT:
				errCh <- nil
				return
			}
		}
	}()

	// Wait for the first goroutine to finish.
	firstErr := <-errCh

	// Cancel the context to unblock the other goroutine. Close appConn to
	// unblock any pending Read on the app-reader goroutine. The context
	// cancellation propagates to stream.Recv() to unblock the tunnel-reader.
	cancel()
	appConn.Close()

	// Drain the second goroutine's result so it can be garbage-collected.
	<-errCh

	log.Printf("[Tunnel Server] Connection %s: closed", connectionID)
	return firstErr
}

// Serve starts the gRPC server.
func (s *Server) Serve(lis net.Listener) error {
	return s.grpcServer.Serve(lis)
}

// Stop gracefully stops the server.
func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
}
