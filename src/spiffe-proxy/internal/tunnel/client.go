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
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/project-aim/spiffe-proxy/internal/tunnel/tunnelpb"
)

// Client manages the gRPC mTLS tunnel to the ingress proxy.
type Client struct {
	conn       *grpc.ClientConn
	client     tunnelpb.TunnelServiceClient
	remoteAddr string
	tlsConfig  *tls.Config
	mu         sync.Mutex
}

// NewClient creates a new tunnel client with mTLS.
func NewClient(remoteAddr string, tlsConfig *tls.Config) (*Client, error) {
	creds := credentials.NewTLS(tlsConfig)

	kaParams := keepalive.ClientParameters{
		Time:                10 * time.Second,
		Timeout:             3 * time.Second,
		PermitWithoutStream: true,
	}

	conn, err := grpc.NewClient(
		remoteAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(kaParams),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to dial remote proxy: %w", err)
	}

	client := &Client{
		conn:       conn,
		client:     tunnelpb.NewTunnelServiceClient(conn),
		remoteAddr: remoteAddr,
		tlsConfig:  tlsConfig,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.client.HealthCheck(ctx, &tunnelpb.HealthCheckRequest{})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("health check failed: %w", err)
	}

	log.Printf("[Tunnel Client] Connected to remote proxy (SPIFFE ID: %s)", resp.SpiffeId)

	return client, nil
}

// ForwardConnection forwards raw TCP/HTTP bytes through the gRPC tunnel.
func (c *Client) ForwardConnection(ctx context.Context, localConn net.Conn, connectionID string) error {
	stream, err := c.client.Tunnel(ctx)
	if err != nil {
		return fmt.Errorf("failed to create tunnel stream: %w", err)
	}

	if err := stream.Send(&tunnelpb.TunnelMessage{
		ConnectionId: connectionID,
		Type:         tunnelpb.MessageType_MESSAGE_TYPE_CONNECT,
		Metadata: map[string]string{
			"remote_addr": localConn.RemoteAddr().String(),
		},
	}); err != nil {
		stream.CloseSend()
		return fmt.Errorf("failed to send connect message: %w", err)
	}

	log.Printf("[Tunnel Client] Connection %s: tunnel stream established", connectionID)

	// Use a cancellable context so we can signal both goroutines to stop
	// when the first one finishes, preventing goroutine leaks.
	copyCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)

	// Local → Remote
	go func() {
		buf := make([]byte, 32*1024)
		for {
			// Check if we've been cancelled before blocking on read.
			select {
			case <-copyCtx.Done():
				errCh <- nil
				return
			default:
			}

			n, err := localConn.Read(buf)
			if err != nil {
				if err == io.EOF {
					stream.Send(&tunnelpb.TunnelMessage{
						ConnectionId: connectionID,
						Type:         tunnelpb.MessageType_MESSAGE_TYPE_DISCONNECT,
					})
					errCh <- nil
				} else {
					errCh <- fmt.Errorf("local read error: %w", err)
				}
				return
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

	// Remote → Local
	go func() {
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
				if _, err := localConn.Write(msg.Payload); err != nil {
					errCh <- fmt.Errorf("local write error: %w", err)
					return
				}
			case tunnelpb.MessageType_MESSAGE_TYPE_DISCONNECT:
				errCh <- nil
				return
			case tunnelpb.MessageType_MESSAGE_TYPE_ERROR:
				errCh <- fmt.Errorf("remote error: %s", string(msg.Payload))
				return
			}
		}
	}()

	// Wait for the first goroutine to finish.
	firstErr := <-errCh

	// Cancel the context to unblock the other goroutine. For the reader
	// goroutine this closes the stream (Recv returns); for the writer
	// goroutine this triggers the localConn read deadline via the
	// select-default check or the context cancellation propagating to the
	// stream. We also close localConn to unblock any pending Read.
	cancel()
	localConn.Close()

	// Drain the second goroutine's result so it can be garbage-collected.
	<-errCh

	// Signal the server that we're done sending.
	stream.CloseSend()

	return firstErr
}

// Close closes the tunnel client.
func (c *Client) Close() error {
	return c.conn.Close()
}
