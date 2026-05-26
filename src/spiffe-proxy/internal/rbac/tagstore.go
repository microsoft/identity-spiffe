package rbac

import (
	"log"
	"sync"
)

// TagStore is a thread-safe in-memory store mapping SPIFFE IDs to custom
// security attribute tags (e.g., "Finance"). Tags are sourced from Microsoft
// Graph API custom security attributes at startup and can be updated at
// runtime via the /mgmt/agent-tags endpoint.
//
// When a tag is present in the TagStore for a caller's SPIFFE ID, it takes
// precedence over the static ca.agent_tag value in the YAML policy. This
// makes enforcement use real Entra attributes instead of hardcoded values.
type TagStore struct {
	mu   sync.RWMutex
	tags map[string]string // SPIFFE ID → tag (e.g., "Finance")
}

// NewTagStore creates an empty TagStore.
func NewTagStore() *TagStore {
	return &TagStore{
		tags: make(map[string]string),
	}
}

// GetTag returns the tag for a SPIFFE ID.
// Returns ("", false) if no tag is set.
func (s *TagStore) GetTag(spiffeID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tag, ok := s.tags[spiffeID]
	return tag, ok
}

// SetTag sets the tag for a SPIFFE ID. Returns the previous tag.
func (s *TagStore) SetTag(spiffeID, tag string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.tags[spiffeID]
	s.tags[spiffeID] = tag
	log.Printf("[TAG] Agent tag updated: %s → %s (was %s)", spiffeID, tag, prev)
	return prev
}

// RemoveTag removes the tag for a SPIFFE ID.
func (s *TagStore) RemoveTag(spiffeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tags, spiffeID)
	log.Printf("[TAG] Agent tag removed: %s", spiffeID)
}

// GetAll returns a snapshot of all tags.
func (s *TagStore) GetAll() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snapshot := make(map[string]string, len(s.tags))
	for k, v := range s.tags {
		snapshot[k] = v
	}
	return snapshot
}

// Count returns the number of stored tags.
func (s *TagStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tags)
}

// GetTagByPrefix returns the tag for the first SPIFFE ID that starts with
// the given prefix. This supports matching when the exact SPIFFE ID isn't
// known but the prefix is (e.g., matching by agent name segment).
func (s *TagStore) GetTagByPrefix(prefix string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for id, tag := range s.tags {
		if len(id) >= len(prefix) && id[:len(prefix)] == prefix {
			return tag, true
		}
	}
	return "", false
}
