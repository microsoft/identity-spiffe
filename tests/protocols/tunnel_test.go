package protocols

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/gateway"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/logging"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/tunnel"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/tunnel/tunnelpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type backendRequest struct {
	path   string
	body   string
	caller string
	agent  string
}

func TestTunnel(t *testing.T) {
	for _, name := range []string{
		"allowed", "denied", "jwt_missing", "ca_disabled", "spoofed_identity", "split_body",
		"second_frame", "same_frame", "overflow_frame",
	} {
		t.Run(name, func(t *testing.T) {
			f := newIdentityFixture(t)
			p := basePolicy()
			if name == "ca_disabled" {
				p.AdminGovernance.Enabled = true
				p.Policies[0].CA.AgentState = "disabled"
			}
			var mu sync.Mutex
			var observed []backendRequest
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
				if err != nil {
					t.Errorf("backend could not read fixture body")
					return
				}
				mu.Lock()
				observed = append(observed, backendRequest{r.URL.Path, string(body),
					r.Header.Get("X-Spiffe-Caller-Id"), r.Header.Get("X-Spiffe-Entra-Agent-Id")})
				mu.Unlock()
				_, _ = io.WriteString(w, "fixture-ok")
			}))
			t.Cleanup(backend.Close)
			serverTLS, clientTLS, auth := tlsPair(t, caller, false, false)
			s := tunnel.NewServer(backend.Listener.Addr().String(), serverTLS, serverID)
			s.SetDynamicAuth(auth)
			s.SetInterceptor(gateway.NewInterceptor(engine(t, p, f.validator(), nil, nil, nil), logging.NewAccessLogger(32)))
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			must(t, listener, err)
			serveDone := make(chan error, 1)
			go func() { serveDone <- s.Serve(listener) }()
			t.Cleanup(func() {
				stopped := make(chan struct{})
				go func() { s.Stop(); close(stopped) }()
				select {
				case <-stopped:
				case <-time.After(5 * time.Second):
					t.Error("production tunnel did not shut down within deadline")
					_ = listener.Close()
				}
				select {
				case err := <-serveDone:
					if err != nil {
						t.Error("local gRPC server failed")
					}
				case <-time.After(time.Second):
					t.Error("gRPC server did not exit")
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			t.Cleanup(cancel)
			connection, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
			must(t, connection, err)
			t.Cleanup(func() { _ = connection.Close() })
			client := tunnelpb.NewTunnelServiceClient(connection)
			health, err := client.HealthCheck(ctx, &tunnelpb.HealthCheckRequest{})
			must(t, health, err)
			if !health.Healthy || health.SpiffeId != serverID {
				t.Fatal("authenticated health check failed")
			}
			stream, err := client.Tunnel(ctx)
			must(t, stream, err)
			send := func(kind tunnelpb.MessageType, payload string) {
				t.Helper()
				if err := stream.Send(&tunnelpb.TunnelMessage{ConnectionId: "fixture-connection", Type: kind, Payload: []byte(payload)}); err != nil {
					t.Fatal("fixture stream send failed")
				}
			}
			send(tunnelpb.MessageType_MESSAGE_TYPE_CONNECT, "")
			token := f.token(t, nil, false)
			if name == "jwt_missing" {
				token = ""
			}
			authHeader := ""
			if token != "" {
				authHeader = "Authorization: Bearer " + token + "\r\n"
			}
			path, method, length, body := "/read", "GET", 0, ""
			if name == "denied" {
				path = "/private"
			}
			if name == "split_body" || name == "overflow_frame" {
				path, method, length, body = "/upload", "POST", 4, "ab"
			}
			closeHeader := "Connection: close\r\n"
			if name == "same_frame" || name == "second_frame" || name == "overflow_frame" {
				closeHeader = ""
			}
			spoof := ""
			if name == "spoofed_identity" {
				spoof = "X-SPIFFE-Caller-ID: spiffe://matrix.test/forged\r\nX-SPIFFE-Entra-Agent-ID: forged-agent\r\n"
			}
			first := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: fixture\r\n%s%s%sContent-Length: %d\r\n\r\n%s",
				method, path, authHeader, closeHeader, spoof, length, body)
			second := "GET /private HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
			if name == "same_frame" {
				first += second
			}
			send(tunnelpb.MessageType_MESSAGE_TYPE_DATA, first)
			if name == "split_body" {
				send(tunnelpb.MessageType_MESSAGE_TYPE_DATA, "cd")
			}
			if name == "overflow_frame" {
				send(tunnelpb.MessageType_MESSAGE_TYPE_DATA, "cd"+second)
			}

			// Read complete first HTTP response; gRPC DATA boundaries need not
			// align with HTTP response boundaries.
			var response strings.Builder
			received := make(chan error, 1)
			readEnd, writeEnd := io.Pipe()
			t.Cleanup(func() { _ = readEnd.Close(); _ = writeEnd.Close() })
			go func() {
				defer writeEnd.Close()
				for {
					message, err := stream.Recv()
					if err != nil {
						received <- err
						return
					}
					if message.Type == tunnelpb.MessageType_MESSAGE_TYPE_DISCONNECT {
						received <- nil
						return
					}
					if message.Type == tunnelpb.MessageType_MESSAGE_TYPE_ERROR {
						received <- fmt.Errorf("production tunnel reported an error")
						return
					}
					if message.Type == tunnelpb.MessageType_MESSAGE_TYPE_DATA {
						if _, err := writeEnd.Write(message.Payload); err != nil {
							received <- err
							return
						}
					}
				}
			}()
			reader := bufio.NewReader(readEnd)
			httpResponse, err := http.ReadResponse(reader, nil)
			must(t, httpResponse, err)
			if _, err := io.Copy(&response, httpResponse.Body); err != nil {
				t.Fatal("incomplete backend/deny response")
			}
			_ = httpResponse.Body.Close()
			wantStatus := 200
			if name == "denied" || name == "ca_disabled" {
				wantStatus = 403
			}
			if name == "jwt_missing" {
				wantStatus = 401
			}
			if httpResponse.StatusCode != wantStatus {
				t.Fatalf("expected HTTP %d, got %d", wantStatus, httpResponse.StatusCode)
			}
			if wantStatus == 200 && response.String() != "fixture-ok" {
				t.Fatal("expected real backend response")
			}
			if name == "second_frame" {
				// A completed one-request stream may already be closed after the
				// first response. EOF rejects the second send; arbitrary errors do
				// not count. Still drain the stream and assert backend dispatch below.
				err := stream.Send(&tunnelpb.TunnelMessage{
					ConnectionId: "fixture-connection",
					Type:         tunnelpb.MessageType_MESSAGE_TYPE_DATA,
					Payload:      []byte(second),
				})
				if err != nil && err != io.EOF {
					t.Fatal("second request send ended in an unexpected transport error")
				}
			}
			if name == "same_frame" || name == "overflow_frame" {
				// Do not half-close early and race the backend's second request.
				// Observe its response or an actual stream close before deciding
				// whether the denied second request escaped the gateway.
				secondResponse, secondErr := http.ReadResponse(reader, nil)
				if secondErr == nil {
					_, _ = io.Copy(io.Discard, secondResponse.Body)
					_ = secondResponse.Body.Close()
				}
			}
			// Half-close only after input delivery and the first response. Draining
			// ends the real server reader even when its app-side peer closed first.
			_ = stream.CloseSend()
			_, _ = io.Copy(io.Discard, reader)
			select {
			case err := <-received:
				if err != nil && err != io.EOF {
					t.Fatal("stream ended in a transport error, not a verified policy outcome")
				}
			case <-ctx.Done():
				t.Fatal("stream did not terminate")
			}
			mu.Lock()
			requests := append([]backendRequest(nil), observed...)
			mu.Unlock()
			t.Logf("PROTOCOL_EVIDENCE {\"backend_requests\":%d}", len(requests))
			wantCount := 1
			if wantStatus != 200 {
				wantCount = 0
			}
			if len(requests) != wantCount {
				t.Fatalf("backend saw %d requests; only %d governed request(s) permitted", len(requests), wantCount)
			}
			if wantCount == 1 {
				if requests[0].caller != caller || requests[0].agent != "fixture-agent" {
					t.Fatal("backend did not receive authenticated identity headers")
				}
				if requests[0].path != path {
					t.Fatal("backend path did not match authorized path")
				}
				if (name == "split_body" || name == "overflow_frame") && requests[0].body != "abcd" {
					t.Fatal("legitimate split body was not preserved")
				}
			}
		})
	}
}
