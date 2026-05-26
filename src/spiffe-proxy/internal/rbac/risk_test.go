package rbac

import (
	"sync"
	"testing"
)

func TestRiskStore_DefaultLow(t *testing.T) {
	rs := NewRiskStore()
	if got := rs.GetRisk("spiffe://unknown"); got != RiskLow {
		t.Errorf("expected %q for unknown agent, got %q", RiskLow, got)
	}
}

func TestRiskStore_SetAndGet(t *testing.T) {
	rs := NewRiskStore()
	prev := rs.SetRisk("spiffe://test", RiskHigh)
	if prev != RiskLow {
		t.Errorf("expected previous level %q, got %q", RiskLow, prev)
	}
	if got := rs.GetRisk("spiffe://test"); got != RiskHigh {
		t.Errorf("expected %q, got %q", RiskHigh, got)
	}
}

func TestRiskStore_SetOverwrite(t *testing.T) {
	rs := NewRiskStore()
	rs.SetRisk("spiffe://test", RiskHigh)
	prev := rs.SetRisk("spiffe://test", RiskLow)
	if prev != RiskHigh {
		t.Errorf("expected previous level %q, got %q", RiskHigh, prev)
	}
	if got := rs.GetRisk("spiffe://test"); got != RiskLow {
		t.Errorf("expected %q, got %q", RiskLow, got)
	}
}

func TestRiskStore_GetAll(t *testing.T) {
	rs := NewRiskStore()
	rs.SetRisk("spiffe://a", RiskHigh)
	rs.SetRisk("spiffe://b", RiskMedium)

	all := rs.GetAll()
	if len(all) != 2 {
		t.Errorf("expected 2 entries, got %d", len(all))
	}
	if all["spiffe://a"] != RiskHigh {
		t.Errorf("expected %q for a, got %q", RiskHigh, all["spiffe://a"])
	}
	if all["spiffe://b"] != RiskMedium {
		t.Errorf("expected %q for b, got %q", RiskMedium, all["spiffe://b"])
	}

	// Verify snapshot isolation — modifying the returned map doesn't affect the store.
	all["spiffe://a"] = RiskLow
	if got := rs.GetRisk("spiffe://a"); got != RiskHigh {
		t.Errorf("snapshot isolation broken: expected %q, got %q", RiskHigh, got)
	}
}

func TestRiskStore_Count(t *testing.T) {
	rs := NewRiskStore()
	if rs.Count() != 0 {
		t.Errorf("expected 0 count, got %d", rs.Count())
	}
	rs.SetRisk("spiffe://a", RiskHigh)
	if rs.Count() != 1 {
		t.Errorf("expected 1 count, got %d", rs.Count())
	}
}

func TestRiskStore_ConcurrentAccess(t *testing.T) {
	rs := NewRiskStore()
	var wg sync.WaitGroup

	// Concurrent writers
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := "spiffe://concurrent"
			if n%2 == 0 {
				rs.SetRisk(id, RiskHigh)
			} else {
				rs.SetRisk(id, RiskLow)
			}
		}(i)
	}

	// Concurrent readers
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			risk := rs.GetRisk("spiffe://concurrent")
			if risk != RiskHigh && risk != RiskLow {
				t.Errorf("unexpected risk level: %q", risk)
			}
		}()
	}

	wg.Wait()
}

func TestValidRiskLevel(t *testing.T) {
	tests := []struct {
		level string
		valid bool
	}{
		{"low", true},
		{"medium", true},
		{"high", true},
		{"", false},
		{"critical", false},
		{"LOW", false}, // case-sensitive
	}
	for _, tt := range tests {
		if got := ValidRiskLevel(tt.level); got != tt.valid {
			t.Errorf("ValidRiskLevel(%q) = %v, want %v", tt.level, got, tt.valid)
		}
	}
}
