// Package logging provides structured access logging for the SPIFFE sidecar gateway.
// It emits JSON log lines for every proxied request and maintains an in-memory
// ring buffer for the /audit management API endpoint.
package logging

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

// AccessEntry represents a single proxied request in the access log.
type AccessEntry struct {
	Timestamp          string   `json:"timestamp"`
	CallerSpiffeID     string   `json:"caller_spiffe_id"`
	EntraAgentID       string   `json:"entra_agent_id,omitempty"`
	Method             string   `json:"method"`
	Path               string   `json:"path"`
	Decision           string   `json:"decision"`
	Reason             string   `json:"reason"`
	EnforcementLayer   string   `json:"enforcement_layer"`
	LatencyMs          int64    `json:"latency_ms"`
	RequestID          string   `json:"request_id"`
	JWTPresent         bool     `json:"jwt_present,omitempty"`
	JWTValid           bool     `json:"jwt_valid,omitempty"`
	JWTAudience        string   `json:"jwt_audience,omitempty"`
	JWTRoles           []string `json:"jwt_roles,omitempty"`
	JWTValidationError string            `json:"jwt_validation_error,omitempty"`
	CustomClaims       map[string]string `json:"custom_claims,omitempty"`
}

// AccessLogger emits structured access logs and stores recent entries.
type AccessLogger struct {
	mu      sync.Mutex
	entries []AccessEntry
	maxSize int
	head    int
	count   int

	// Counters for /metrics.
	totalRequests int64
	totalAllowed  int64
	totalDenied   int64
	perCaller     map[string]*CallerMetrics

	// Pub/sub fan-out for live streaming.
	subs   map[int]subscription
	nextID int
}

// subscription is a single live Subscribe() registration. Log() sends
// new entries on ch with a non-blocking select; if done is closed, the
// entry is dropped for this subscriber. We never close ch itself —
// doing so from cancel() would race with Log()'s send. The channel is
// reclaimed by GC when the cancel caller releases its reference.
type subscription struct {
	ch   chan AccessEntry
	done chan struct{}
}

// CallerMetrics tracks per-SPIFFE-ID request stats.
type CallerMetrics struct {
	Allowed int64 `json:"allowed"`
	Denied  int64 `json:"denied"`
	Total   int64 `json:"total"`
}

// NewAccessLogger creates a logger with a ring buffer of the given capacity.
func NewAccessLogger(maxEntries int) *AccessLogger {
	return &AccessLogger{
		entries:   make([]AccessEntry, maxEntries),
		maxSize:   maxEntries,
		perCaller: make(map[string]*CallerMetrics),
		subs:      make(map[int]subscription),
	}
}

// Log records an access entry, emits it to stdout, and updates counters.
func (al *AccessLogger) Log(entry AccessEntry) {
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	// Emit structured JSON log line.
	data, _ := json.Marshal(entry)
	log.Printf("[ACCESS] %s", string(data))

	al.mu.Lock()

	// Ring buffer insert.
	al.entries[al.head] = entry
	al.head = (al.head + 1) % al.maxSize
	if al.count < al.maxSize {
		al.count++
	}

	// Update counters.
	al.totalRequests++
	if entry.Decision == "allow" {
		al.totalAllowed++
	} else {
		al.totalDenied++
	}

	cm, ok := al.perCaller[entry.CallerSpiffeID]
	if !ok {
		cm = &CallerMetrics{}
		al.perCaller[entry.CallerSpiffeID] = cm
	}
	cm.Total++
	if entry.Decision == "allow" {
		cm.Allowed++
	} else {
		cm.Denied++
	}

	// Snapshot subscriptions under the lock so we can fan out without holding it.
	subs := make([]subscription, 0, len(al.subs))
	for _, sub := range al.subs {
		subs = append(subs, sub)
	}
	al.mu.Unlock()

	// Non-blocking fan-out: drop the entry for any subscriber whose buffer
	// is full OR whose cancel has been invoked (done closed). This avoids
	// a send-on-closed-channel race that would otherwise exist if we
	// closed ch from cancel().
	for _, sub := range subs {
		select {
		case <-sub.done:
			// Cancelled; drop.
		case sub.ch <- entry:
		default:
		}
	}
}

// LogMTLSRejection records an mTLS handshake rejection.
// At the TLS layer, no HTTP method/path is available — only the caller's SPIFFE ID.
// This feeds transport-layer enforcement decisions into the same audit trail as RBAC.
func (al *AccessLogger) LogMTLSRejection(callerSpiffeID string) {
	al.Log(AccessEntry{
		CallerSpiffeID:   callerSpiffeID,
		Method:           "",
		Path:             "",
		Decision:         "deny",
		Reason:           "mtls_rejected",
		EnforcementLayer: "mtls",
		LatencyMs:        0,
		RequestID:        "",
	})
}

// Subscribe returns a buffered channel of new entries and a cancel function.
// The channel has capacity 128; if a subscriber cannot keep up, new entries
// are dropped silently for that subscriber (streaming is best-effort, not a
// durable queue). The channel is NOT closed on cancel — readers should stop
// reading after cancel returns. The done channel is closed so Log() can
// drop entries for cancelled subscribers without a send-on-closed-channel
// race.
func (al *AccessLogger) Subscribe() (<-chan AccessEntry, func()) {
	sub := subscription{
		ch:   make(chan AccessEntry, 128),
		done: make(chan struct{}),
	}
	al.mu.Lock()
	id := al.nextID
	al.nextID++
	al.subs[id] = sub
	al.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			al.mu.Lock()
			if existing, ok := al.subs[id]; ok {
				delete(al.subs, id)
				close(existing.done)
			}
			al.mu.Unlock()
		})
	}
	return sub.ch, cancel
}

// Recent returns the most recent entries, newest first.
// Supports optional filtering by spiffeID and/or decision.
func (al *AccessLogger) Recent(limit int, spiffeIDFilter, decisionFilter string) []AccessEntry {
	al.mu.Lock()
	defer al.mu.Unlock()

	if limit <= 0 || limit > al.count {
		limit = al.count
	}

	var result []AccessEntry
	// Walk backwards from the most recent entry.
	for i := 0; i < al.count && len(result) < limit; i++ {
		idx := (al.head - 1 - i + al.maxSize) % al.maxSize
		entry := al.entries[idx]

		if spiffeIDFilter != "" && entry.CallerSpiffeID != spiffeIDFilter {
			continue
		}
		if decisionFilter != "" && entry.Decision != decisionFilter {
			continue
		}
		result = append(result, entry)
	}
	return result
}

// Metrics returns aggregate request statistics.
type Metrics struct {
	TotalRequests int64                     `json:"total_requests"`
	TotalAllowed  int64                     `json:"total_allowed"`
	TotalDenied   int64                     `json:"total_denied"`
	PerCaller     map[string]*CallerMetrics `json:"per_caller"`
}

// GetMetrics returns current counters.
func (al *AccessLogger) GetMetrics() Metrics {
	al.mu.Lock()
	defer al.mu.Unlock()

	// Deep copy per-caller map.
	callerCopy := make(map[string]*CallerMetrics, len(al.perCaller))
	for k, v := range al.perCaller {
		callerCopy[k] = &CallerMetrics{
			Allowed: v.Allowed,
			Denied:  v.Denied,
			Total:   v.Total,
		}
	}

	return Metrics{
		TotalRequests: al.totalRequests,
		TotalAllowed:  al.totalAllowed,
		TotalDenied:   al.totalDenied,
		PerCaller:     callerCopy,
	}
}
