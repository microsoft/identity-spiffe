package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/gateway"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/logging"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/rbac"
	"github.com/microsoft/identity-spiffe/src/spiffe-proxy/internal/tunnel/tunnelpb"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

const testCaller = "spiffe://fixture.test/caller"

type testStream struct {
	ctx context.Context
	in  chan *tunnelpb.TunnelMessage
	out chan *tunnelpb.TunnelMessage
}

func (s *testStream) Context() context.Context     { return s.ctx }
func (s *testStream) SetHeader(metadata.MD) error  { return nil }
func (s *testStream) SendHeader(metadata.MD) error { return nil }
func (s *testStream) SetTrailer(metadata.MD)       {}
func (s *testStream) SendMsg(any) error            { panic("unused") }
func (s *testStream) RecvMsg(any) error            { panic("unused") }
func (s *testStream) Recv() (*tunnelpb.TunnelMessage, error) {
	select {
	case msg, ok := <-s.in:
		if !ok {
			return nil, io.EOF
		}
		return msg, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}
func (s *testStream) Send(msg *tunnelpb.TunnelMessage) error {
	select {
	case s.out <- msg:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func TestTunnelRequestFraming(t *testing.T) {
	second := "GET /private HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n"
	header := "POST /upload HTTP/1.1\r\nHost: fixture\r\n"
	largeBody := strings.Repeat("body", 400000)
	for _, tc := range []struct {
		name   string
		frames []string
		body   string
	}{
		{"same_frame", []string{"GET /read HTTP/1.1\r\nHost: fixture\r\n\r\n" + second}, ""},
		{"initial_body_overflow", []string{header + "Content-Length: 4\r\n\r\nabcd" + second}, "abcd"},
		{"continuation_overflow", []string{header + "Content-Length: 4\r\n\r\nab", "cd" + second}, "abcd"},
		{"exact_body_boundary", []string{header + "Content-Length: 4\r\n\r\nab", "cd", second}, "abcd"},
		{"split_headers", []string{"POST /up", "load HTTP/1.1\r\nHost: fixture\r\nContent-Len", "gth: 4\r\n\r", "\nab", "", "cd"}, "abcd"},
		{"body_is_not_a_request", []string{header + "Content-Length: " + strconv.Itoa(len(second)) + "\r\n\r\n", second}, second},
		{"chunked", []string{header + "Transfer-Encoding: chunked\r\n\r\n2\r\nab\r", "\n2\r\ncd\r\n0\r\n\r\n" + second}, "abcd"},
		{"chunk_extensions", []string{header + "Transfer-Encoding: chunked\r\n\r\n4;ext=value\r\nabcd\r\n0\r\n\r\n" + second}, "abcd"},
		{"chunked_with_content_length", []string{header + "Content-Length: 1000\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n" + second}, "abcd"},
		{"trailers", []string{header + "Transfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n4\r\nabcd\r\n0\r\nX-Checksum: test\r\n\r\n" + second}, "abcd"},
		{"lf_headers", []string{"POST /upload HTTP/1.1\nHost: fixture\nContent-Length: 4\n\nabcd" + second}, "abcd"},
		{"large_streamed_body", append([]string{header + "Content-Length: 1600000\r\n\r\n"}, splitFrames(largeBody)...), largeBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var bodies []string
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Errorf("backend body: %v", err)
					return
				}
				if req.Header.Get("X-Spiffe-Caller-Id") != testCaller {
					t.Error("authenticated caller header not injected")
				}
				if tc.name == "trailers" && req.Trailer.Get("X-Checksum") != "test" {
					t.Error("legitimate chunk trailer was not preserved")
				}
				mu.Lock()
				bodies = append(bodies, string(body))
				mu.Unlock()
				_, _ = io.WriteString(w, "ok")
			}))
			defer backend.Close()
			response, err := runTestTunnel(t, backend, tc.frames, false)
			if err != nil {
				t.Fatalf("tunnel failed: %v", err)
			}
			reader := bufio.NewReader(bytes.NewReader(response))
			resp, err := http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatalf("first response: %v", err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || resp.StatusCode != 200 || string(body) != "ok" {
				t.Fatalf("allowed request lost: status=%d body=%q err=%v", resp.StatusCode, body, err)
			}
			if !resp.Close {
				t.Error("one-request tunnel must advertise Connection: close")
			}
			if _, err := reader.Peek(1); err != io.EOF {
				t.Errorf("unexpected bytes after first response: %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(bodies) != 1 || bodies[0] != tc.body {
				t.Errorf("backend requests=%d, expected exactly one intact body", len(bodies))
			}
		})
	}
}

func TestTunnelIncompleteFraming(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"headers", "GET /read HTTP/1.1\r\nHost: fixture"},
		{"content_length", "POST /upload HTTP/1.1\r\nHost: fixture\r\nContent-Length: 4\r\n\r\nab"},
		{"chunk_data", "POST /upload HTTP/1.1\r\nHost: fixture\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nab"},
		{"chunk_terminator", "POST /upload HTTP/1.1\r\nHost: fixture\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n"},
		{"bad_chunk_size", "POST /upload HTTP/1.1\r\nHost: fixture\r\nTransfer-Encoding: chunked\r\n\r\nnope\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			count := 0
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if _, err := io.ReadAll(req.Body); err == nil {
					mu.Lock()
					count++
					mu.Unlock()
				}
			}))
			defer backend.Close()
			// Half-close input after delivering the partial request.
			_, err := runTestTunnel(t, backend, []string{tc.raw}, true)
			if tc.name != "headers" && err == nil {
				t.Error("incomplete/malformed body must report a forwarding error")
			}
			mu.Lock()
			defer mu.Unlock()
			if count != 0 {
				t.Errorf("backend received %d complete malformed requests", count)
			}
		})
	}
}

func TestTunnelEarlyBackendResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Consume delivered bytes to avoid an unread-data TCP reset, but leave
		// the rest of this large body stalled in the tunnel's Recv.
		if _, err := io.ReadFull(req.Body, make([]byte, 2)); err != nil {
			t.Errorf("initial body bytes: %v", err)
			return
		}
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer backend.Close()
	frames := []string{"POST /upload HTTP/1.1\r\nHost: fixture\r\nContent-Length: 4000000\r\n\r\nab"}
	start := time.Now()
	response, err := runTestTunnel(t, backend, frames, false)
	if err != nil {
		t.Fatalf("early response: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(response)), nil)
	if err != nil || resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("backend response lost or tunnel stalled: %v", err)
	}
	_ = resp.Body.Close()
	if time.Since(start) >= time.Second {
		t.Error("early backend response waited for stalled input to time out")
	}
}

func splitFrames(body string) []string {
	var frames []string
	for len(body) > 0 {
		n := min(len(body), 32*1024)
		frames = append(frames, body[:n])
		body = body[n:]
	}
	return frames
}

func TestTunnelRejectsInvalidFraming(t *testing.T) {
	for _, raw := range []string{
		"GET /read HTTP/1.1\r\nHost: fixture\r\nContent-Length: -1\r\n\r\n",
		"GET /read HTTP/1.1\r\nHost: fixture\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n",
		"GET /read HTTP/1.1\r\nHost: fixture\r\nTransfer-Encoding: gzip\r\n\r\n",
		"GET /read HTTP/1.1\r\nHost: fixture\r\nX-Large: " + strings.Repeat("x", 65536) + "\r\n\r\n",
	} {
		t.Run(strings.Split(raw, "\r\n")[2][:min(20, len(strings.Split(raw, "\r\n")[2]))], func(t *testing.T) {
			var mu sync.Mutex
			count := 0
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				count++
				mu.Unlock()
			}))
			defer backend.Close()
			response, err := runTestTunnel(t, backend, []string{raw}, false)
			if err != nil {
				t.Fatalf("header denial: %v", err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(response)), nil)
			if err != nil || resp.StatusCode != 403 {
				t.Fatalf("invalid headers must be explicitly denied: %v", err)
			}
			_ = resp.Body.Close()
			mu.Lock()
			defer mu.Unlock()
			if count != 0 {
				t.Fatalf("malformed request dispatched %d times", count)
			}
		})
	}
}

func runTestTunnel(t *testing.T, backend *httptest.Server, frames []string, halfClose bool) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = peer.NewContext(ctx, &peer.Peer{AuthInfo: credentials.TLSInfo{State: tlsState()}})
	stream := &testStream{ctx: ctx, in: make(chan *tunnelpb.TunnelMessage, len(frames)+1), out: make(chan *tunnelpb.TunnelMessage, 128)}
	stream.in <- &tunnelpb.TunnelMessage{ConnectionId: "test", Type: tunnelpb.MessageType_MESSAGE_TYPE_CONNECT}
	for _, frame := range frames {
		stream.in <- &tunnelpb.TunnelMessage{Type: tunnelpb.MessageType_MESSAGE_TYPE_DATA, Payload: []byte(frame)}
	}
	if halfClose {
		close(stream.in)
	}
	store := rbac.NewPolicyStore()
	err := store.LoadFromBytes([]byte(`version: "3.0"
trust_domain: fixture.test
default_action: deny
policies:
  - spiffe_id: spiffe://fixture.test/caller
    name: caller
    rules:
      - path: /read
        methods: [GET]
        action: allow
      - path: /upload
        methods: [POST]
        action: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{appAddr: backend.Listener.Addr().String(), connections: make(map[string]net.Conn), maxConnections: 1}
	server.SetInterceptor(gateway.NewInterceptor(rbac.NewEngine(store, nil, nil, nil), logging.NewAccessLogger(32)))
	done := make(chan error, 1)
	go func() {
		err := server.Tunnel(stream)
		cancel()
		done <- err
	}()
	var response bytes.Buffer
	for {
		select {
		case msg := <-stream.out:
			if msg.Type == tunnelpb.MessageType_MESSAGE_TYPE_DATA {
				response.Write(msg.Payload)
			}
		case err := <-done:
			for len(stream.out) > 0 {
				msg := <-stream.out
				if msg.Type == tunnelpb.MessageType_MESSAGE_TYPE_DATA {
					response.Write(msg.Payload)
				}
			}
			return response.Bytes(), err
		case <-ctx.Done():
			select {
			case err := <-done:
				return response.Bytes(), err
			case <-time.After(time.Second):
				t.Fatal("tunnel did not stop after context cancellation")
			}
		}
	}
}

func tlsState() tls.ConnectionState {
	uri, _ := url.Parse(testCaller)
	return tls.ConnectionState{PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{uri}}}}
}
