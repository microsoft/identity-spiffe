package protocols

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/gateway"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/logging"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/tunnel"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/tunnel/tunnelpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestTunnelCancellationReleasesBackend(t *testing.T) {
	f := newIdentityFixture(t)
	dispatched, released := make(chan struct{}), make(chan struct{})
	finish := make(chan struct{})
	defer close(finish)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		close(dispatched)
		select {
		case <-req.Context().Done():
			close(released)
		case <-finish:
		}
	}))
	t.Cleanup(backend.Close)
	serverTLS, clientTLS, auth := tlsPair(t, caller, false, false)
	server := tunnel.NewServer(backend.Listener.Addr().String(), serverTLS, serverID)
	server.SetDynamicAuth(auth)
	server.SetInterceptor(gateway.NewInterceptor(engine(t, basePolicy(), f.validator(), nil, nil, nil), logging.NewAccessLogger(32)))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, listener, err)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		if err := <-done; err != nil {
			t.Errorf("gRPC serve: %v", err)
		}
	})
	connection, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	must(t, connection, err)
	t.Cleanup(func() { _ = connection.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	health, err := tunnelpb.NewTunnelServiceClient(connection).HealthCheck(ctx, &tunnelpb.HealthCheckRequest{})
	must(t, health, err)
	streamCtx, cancelStream := context.WithCancel(ctx)
	stream, err := tunnelpb.NewTunnelServiceClient(connection).Tunnel(streamCtx)
	must(t, stream, err)
	send := func(kind tunnelpb.MessageType, payload string) {
		t.Helper()
		if err := stream.Send(&tunnelpb.TunnelMessage{ConnectionId: "cancel-test", Type: kind, Payload: []byte(payload)}); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	send(tunnelpb.MessageType_MESSAGE_TYPE_CONNECT, "")
	send(tunnelpb.MessageType_MESSAGE_TYPE_DATA, "GET /read HTTP/1.1\r\nHost: fixture\r\nAuthorization: Bearer "+f.token(t, nil, false)+"\r\n\r\n")
	select {
	case <-dispatched:
	case <-ctx.Done():
		t.Fatal("healthy authorized control did not reach backend")
	}
	cancelStream()
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("cancelled stream retained its backend connection")
	}

	// Reusing the connection ID proves the abandoned stream's slot was removed.
	probe, err := tunnelpb.NewTunnelServiceClient(connection).Tunnel(ctx)
	must(t, probe, err)
	for _, msg := range []*tunnelpb.TunnelMessage{
		{ConnectionId: "cancel-test", Type: tunnelpb.MessageType_MESSAGE_TYPE_CONNECT},
		{Type: tunnelpb.MessageType_MESSAGE_TYPE_DATA, Payload: []byte("GET /private HTTP/1.1\r\nHost: fixture\r\n\r\n")},
	} {
		if err := probe.Send(msg); err != nil {
			t.Fatalf("slot reuse send: %v", err)
		}
	}
	var response strings.Builder
	for {
		msg, err := probe.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("connection slot not reclaimed: %v", err)
		}
		if msg.Type == tunnelpb.MessageType_MESSAGE_TYPE_DATA {
			response.Write(msg.Payload)
		}
	}
	if !strings.HasPrefix(response.String(), "HTTP/1.1 403 Forbidden\r\n") {
		t.Fatal("reused stream did not reach gateway authorization")
	}
}
