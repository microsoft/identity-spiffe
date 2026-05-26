package logging

import (
"testing"
)

// TestCancelIdempotent verifies that calling cancel() multiple times is safe
func TestCancelIdempotent(t *testing.T) {
al := NewAccessLogger(100)
_, cancel := al.Subscribe()

// Call cancel multiple times - should not panic
cancel()
cancel()
cancel()
}
