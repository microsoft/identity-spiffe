package mtls

import (
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var (
	td = spiffeid.RequireTrustDomainFromString("aim.microsoft.com")

	budgetReport   = spiffeid.RequireFromPath(td, "/ests/bp/test-bp-oid/aid/budget-report")
	budgetBackend  = spiffeid.RequireFromPath(td, "/ests/bp/test-bp-oid/aid/budget-backend")
	employeeMenus  = spiffeid.RequireFromPath(td, "/ests/bp/test-bp-oid/aid/employee-menus")
	budgetApproval = spiffeid.RequireFromPath(td, "/ests/bp/test-bp-oid/aid/budget-approval")
)

func TestAuthorize_Allowed(t *testing.T) {
	auth := NewDynamicAuthorizer(
		[]spiffeid.ID{budgetReport, budgetApproval},
		nil,
	)
	if err := auth.Authorize(budgetReport); err != nil {
		t.Fatalf("budgetReport should be allowed: %v", err)
	}
	if err := auth.Authorize(budgetApproval); err != nil {
		t.Fatalf("budgetApproval should be allowed: %v", err)
	}
}

func TestAuthorize_Rejected(t *testing.T) {
	rejectedCh := make(chan string, 1)
	auth := NewDynamicAuthorizer(
		[]spiffeid.ID{budgetReport},
		func(callerSpiffeID string) {
			rejectedCh <- callerSpiffeID
		},
	)
	err := auth.Authorize(employeeMenus)
	if err == nil {
		t.Fatal("employeeMenus should be rejected")
	}
	select {
	case got := <-rejectedCh:
		if got != employeeMenus.String() {
			t.Errorf("expected rejection callback for %s, got %q", employeeMenus, got)
		}
	case <-time.After(time.Second):
		t.Error("rejection callback was not called within 1s")
	}
}

func TestUpdate_AtomicReplace(t *testing.T) {
	auth := NewDynamicAuthorizer([]spiffeid.ID{budgetReport}, nil)
	if err := auth.Authorize(budgetReport); err != nil {
		t.Fatalf("budgetReport should be allowed initially: %v", err)
	}
	auth.Update([]spiffeid.ID{employeeMenus})
	if err := auth.Authorize(employeeMenus); err != nil {
		t.Fatalf("employeeMenus should be allowed after update: %v", err)
	}
	if err := auth.Authorize(budgetReport); err == nil {
		t.Fatal("budgetReport should be rejected after update")
	}
}

func TestAdd_Remove(t *testing.T) {
	auth := NewDynamicAuthorizer(nil, nil)
	if auth.Count() != 0 {
		t.Fatalf("expected 0 IDs, got %d", auth.Count())
	}
	auth.Add(budgetReport)
	if !auth.Contains(budgetReport) {
		t.Fatal("budgetReport should be in list after Add")
	}
	if auth.Count() != 1 {
		t.Fatalf("expected 1 ID, got %d", auth.Count())
	}
	auth.Add(employeeMenus)
	if auth.Count() != 2 {
		t.Fatalf("expected 2 IDs, got %d", auth.Count())
	}
	auth.Remove(budgetReport)
	if auth.Contains(budgetReport) {
		t.Fatal("budgetReport should not be in list after Remove")
	}
	if auth.Count() != 1 {
		t.Fatalf("expected 1 ID, got %d", auth.Count())
	}
	if err := auth.Authorize(employeeMenus); err != nil {
		t.Fatalf("employeeMenus should be allowed: %v", err)
	}
	if err := auth.Authorize(budgetReport); err == nil {
		t.Fatal("budgetReport should be rejected after Remove")
	}
}

func TestList_Sorted(t *testing.T) {
	auth := NewDynamicAuthorizer(
		[]spiffeid.ID{budgetApproval, budgetReport, employeeMenus},
		nil,
	)
	ids := auth.List()
	if len(ids) != 3 {
		t.Fatalf("expected 3 IDs, got %d", len(ids))
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1].String() >= ids[i].String() {
			t.Errorf("list not sorted: %s >= %s", ids[i-1], ids[i])
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	auth := NewDynamicAuthorizer([]spiffeid.ID{budgetReport}, nil)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(4)
		go func() {
			defer wg.Done()
			auth.Authorize(budgetReport)
		}()
		go func() {
			defer wg.Done()
			auth.Add(employeeMenus)
		}()
		go func() {
			defer wg.Done()
			auth.Remove(employeeMenus)
		}()
		go func() {
			defer wg.Done()
			auth.Update([]spiffeid.ID{budgetReport, budgetApproval})
		}()
	}
	wg.Wait()
}

func TestEmptyAllowList_RejectsAll(t *testing.T) {
	auth := NewDynamicAuthorizer(nil, nil)
	if err := auth.Authorize(budgetReport); err == nil {
		t.Fatal("empty allow list should reject all")
	}
	if err := auth.Authorize(employeeMenus); err == nil {
		t.Fatal("empty allow list should reject all")
	}
}
