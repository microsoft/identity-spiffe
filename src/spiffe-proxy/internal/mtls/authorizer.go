// Package mtls provides a dynamic mTLS authorizer that can be updated at runtime
// via the management API. Unlike the static go-spiffe AuthorizeOneOf, this authorizer
// maintains a mutable allow list of SPIFFE IDs that can be modified without restarting
// the proxy. This enables the "progressive hardening" demo: start with all agents
// allowed, then remove them one by one through the portal.
package mtls

import (
	"fmt"
	"log"
	"sort"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// OnRejectFunc is called when a TLS handshake is rejected because the caller's
// SPIFFE ID is not in the allow list. Used to feed mTLS rejections into the
// access logger.
type OnRejectFunc func(callerSpiffeID string)

// DynamicAuthorizer maintains a thread-safe mutable allow list of SPIFFE IDs.
// It provides an Authorize function compatible with the go-spiffe tlsconfig
// authorizer pattern, but the allow list can be updated at runtime.
type DynamicAuthorizer struct {
	mu       sync.RWMutex
	allowed  map[spiffeid.ID]bool
	onReject OnRejectFunc
}

// NewDynamicAuthorizer creates a new authorizer with the given initial allow list.
// The onReject callback is invoked (in a goroutine) whenever a handshake is rejected.
// It may be nil if no rejection logging is needed.
func NewDynamicAuthorizer(initialIDs []spiffeid.ID, onReject OnRejectFunc) *DynamicAuthorizer {
	allowed := make(map[spiffeid.ID]bool, len(initialIDs))
	for _, id := range initialIDs {
		allowed[id] = true
	}
	return &DynamicAuthorizer{
		allowed:  allowed,
		onReject: onReject,
	}
}

// Authorize checks if the given SPIFFE ID is in the allow list.
// This is called by the TLS stack during every mTLS handshake.
// Returns nil if allowed, error if rejected.
func (d *DynamicAuthorizer) Authorize(actual spiffeid.ID) error {
	d.mu.RLock()
	ok := d.allowed[actual]
	d.mu.RUnlock()

	if !ok {
		log.Printf("[mTLS] ❌ REJECTED: %s not in dynamic allow list", actual.String())
		if d.onReject != nil {
			// Fire asynchronously so we don't block the TLS handshake.
			go d.onReject(actual.String())
		}
		return fmt.Errorf("spiffe ID %q is not in the allow list", actual.String())
	}

	log.Printf("[mTLS] ✓ Authorized: %s", actual.String())
	return nil
}

// Update replaces the entire allow list atomically.
func (d *DynamicAuthorizer) Update(ids []spiffeid.ID) {
	newAllowed := make(map[spiffeid.ID]bool, len(ids))
	for _, id := range ids {
		newAllowed[id] = true
	}
	d.mu.Lock()
	d.allowed = newAllowed
	d.mu.Unlock()
	log.Printf("[mTLS] Allow list updated: %d identities", len(ids))
}

// Add adds a single SPIFFE ID to the allow list.
func (d *DynamicAuthorizer) Add(id spiffeid.ID) {
	d.mu.Lock()
	d.allowed[id] = true
	d.mu.Unlock()
	log.Printf("[mTLS] Added to allow list: %s", id.String())
}

// Remove removes a single SPIFFE ID from the allow list.
func (d *DynamicAuthorizer) Remove(id spiffeid.ID) {
	d.mu.Lock()
	delete(d.allowed, id)
	d.mu.Unlock()
	log.Printf("[mTLS] Removed from allow list: %s", id.String())
}

// List returns all currently allowed SPIFFE IDs, sorted for deterministic output.
func (d *DynamicAuthorizer) List() []spiffeid.ID {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]spiffeid.ID, 0, len(d.allowed))
	for id := range d.allowed {
		result = append(result, id)
	}
	// Sort for deterministic API responses.
	sort.Slice(result, func(i, j int) bool {
		return result[i].String() < result[j].String()
	})
	return result
}

// Contains checks if a SPIFFE ID is in the allow list.
func (d *DynamicAuthorizer) Contains(id spiffeid.ID) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.allowed[id]
}

// Count returns the number of allowed SPIFFE IDs.
func (d *DynamicAuthorizer) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.allowed)
}
