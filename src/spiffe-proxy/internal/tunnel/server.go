package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/gateway"
	aimtls "github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/mtls"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/tunnel/tunnelpb"
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
// When set, one parsed HTTP request per stream is authorized and forwarded.
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
//   - HTTP headers are parsed across DATA frames and RBAC-evaluated
//   - If allowed: caller context headers are injected and the modified request is forwarded
//   - If denied: HTTP 403 is sent back through the tunnel; the app never sees the request
//   - SECURITY: Only one HTTP request is permitted per tunnel connection when RBAC is active.
//     Only the parsed request body is streamed to the backend; excess bytes are never
//     forwarded. The backend connection closes after its response.
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

	responseDone := make(chan error, 1)

	// App response → gRPC tunnel → caller
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := appConn.Read(buf)
			// Check if cancelled before sending on the stream to avoid
			// "send on closed stream" panics.
			select {
			case <-copyCtx.Done():
				responseDone <- nil
				return
			default:
			}
			if n > 0 {
				if err := stream.Send(&tunnelpb.TunnelMessage{
					ConnectionId: connectionID,
					Type:         tunnelpb.MessageType_MESSAGE_TYPE_DATA,
					Payload:      buf[:n],
				}); err != nil {
					responseDone <- fmt.Errorf("tunnel send error: %w", err)
					return
				}
			}
			if err != nil {
				if err == io.EOF || copyCtx.Err() != nil {
					responseDone <- nil
				} else {
					responseDone <- fmt.Errorf("app read error: %w", err)
				}
				return
			}
		}
	}()

	type requestResult struct {
		forwarded bool
		err       error
	}
	requestDone := make(chan requestResult, 1)
	go func() {
		forwarded, err := s.forwardRequest(stream, appConn, callerSpiffeID, connectionID)
		requestDone <- requestResult{forwarded, err}
	}()

	for {
		select {
		case result := <-requestDone:
			if result.err != nil || !result.forwarded {
				cancel()
				appConn.Close()
				<-responseDone
				return result.err
			}
			requestDone = nil
		case <-stream.Context().Done():
			cancel()
			appConn.Close()
			<-responseDone
			return stream.Context().Err()
		case err := <-responseDone:
			// Returning the handler cancels the actual gRPC stream and unblocks Recv.
			// A local child context does not cancel ServerStream.Recv, so joining the
			// request writer here would deadlock on an incomplete body/early response.
			return err
		}
	}
}

// tunnelReader exposes DATA frames as bytes without interpreting HTTP framing.
type tunnelReader struct {
	stream  tunnelpb.TunnelService_TunnelServer
	pending []byte
}

func (r *tunnelReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(r.pending) == 0 {
		msg, err := r.stream.Recv()
		if err != nil {
			return 0, err
		}
		switch msg.Type {
		case tunnelpb.MessageType_MESSAGE_TYPE_DATA:
			r.pending = msg.Payload
		case tunnelpb.MessageType_MESSAGE_TYPE_DISCONNECT:
			return 0, io.EOF
		default:
			return 0, fmt.Errorf("unexpected tunnel message type: %v", msg.Type)
		}
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func (s *Server) forwardRequest(stream tunnelpb.TunnelService_TunnelServer, appConn net.Conn, callerID, connectionID string) (bool, error) {
	input := &tunnelReader{stream: stream}
	if s.interceptor == nil {
		_, err := io.Copy(appConn, input)
		return false, err
	}

	// Bound header buffering, then remove the limit for the streamed body.
	// ReadRequest's Body stops at Content-Length or the final chunk/trailers,
	// even if the reader prefetched a second request from the same DATA frame.
	limited := &io.LimitedReader{R: input, N: 64 * 1024}
	req, err := http.ReadRequest(bufio.NewReader(limited))
	if err != nil {
		log.Printf("[Tunnel Server] Connection %s: invalid or incomplete HTTP headers", connectionID)
		if stream.Context().Err() != nil {
			return false, err
		}
		req = nil
	}
	result := s.interceptor.Process(callerID, req)
	if !result.Allowed {
		if err := stream.Send(&tunnelpb.TunnelMessage{
			ConnectionId: connectionID,
			Type:         tunnelpb.MessageType_MESSAGE_TYPE_DATA,
			Payload:      result.DenyResponse,
		}); err != nil {
			return false, fmt.Errorf("send deny response: %w", err)
		}
		return false, stream.Send(&tunnelpb.TunnelMessage{
			ConnectionId: connectionID,
			Type:         tunnelpb.MessageType_MESSAGE_TYPE_DISCONNECT,
		})
	}

	limited.N = math.MaxInt64
	req.Close = true
	req.Header.Del("Connection")
	if err := req.Write(appConn); err != nil {
		log.Printf("[Tunnel Server] Connection %s: HTTP request forwarding failed", connectionID)
		return false, fmt.Errorf("forward HTTP request: %w", err)
	}
	return true, req.Body.Close()
}

// Serve starts the gRPC server.
func (s *Server) Serve(lis net.Listener) error {
	return s.grpcServer.Serve(lis)
}

// Stop gracefully stops the server.
func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
}
