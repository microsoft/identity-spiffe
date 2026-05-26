package logging

import (
	"sync"
	"testing"
	"time"
)

func TestSubscribeFanOut(t *testing.T) {
	al := NewAccessLogger(100)

	chA, cancelA := al.Subscribe()
	chB, cancelB := al.Subscribe()
	chC, cancelC := al.Subscribe()
	defer cancelA()
	defer cancelB()
	defer cancelC()

	const n = 50
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			al.Log(AccessEntry{CallerSpiffeID: "spiffe://t/x", Decision: "allow", Path: "/p"})
		}
	}()

	countCh := func(ch <-chan AccessEntry) int {
		count := 0
		deadline := time.After(2 * time.Second)
		for count < n {
			select {
			case <-ch:
				count++
			case <-deadline:
				return count
			}
		}
		return count
	}

	if got := countCh(chA); got != n {
		t.Errorf("subscriber A: got %d entries, want %d", got, n)
	}
	if got := countCh(chB); got != n {
		t.Errorf("subscriber B: got %d entries, want %d", got, n)
	}
	if got := countCh(chC); got != n {
		t.Errorf("subscriber C: got %d entries, want %d", got, n)
	}
	wg.Wait()
}

func TestSubscribeCancel(t *testing.T) {
	al := NewAccessLogger(100)

	ch, cancel := al.Subscribe()

	// Entries published before cancel should be deliverable.
	al.Log(AccessEntry{CallerSpiffeID: "spiffe://t/x", Decision: "allow"})
	select {
	case <-ch:
		// ok
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected entry before cancel")
	}

	cancel()

	// Entries published after cancel must be dropped for this subscriber.
	for i := 0; i < 10; i++ {
		al.Log(AccessEntry{CallerSpiffeID: "spiffe://t/x", Decision: "allow"})
	}

	// Allow a brief window for any in-flight send that might have raced.
	time.Sleep(50 * time.Millisecond)

	select {
	case entry, ok := <-ch:
		if !ok {
			t.Error("channel should NOT be closed by cancel (GC reclaims it)")
		} else {
			t.Errorf("expected no entries after cancel, got %+v", entry)
		}
	default:
		// Expected: no entries, channel still open.
	}

	// Second cancel must be a no-op (idempotent).
	cancel()
}

func TestSubscribeSlowConsumer(t *testing.T) {
	al := NewAccessLogger(100)

	slow, cancelSlow := al.Subscribe()
	fast, cancelFast := al.Subscribe()
	defer cancelSlow()
	defer cancelFast()

	const n = 500

	// Drain "fast" concurrently with publishing so its 128-slot buffer
	// doesn't fill. "slow" is never read, so it will drop entries.
	var fastCount int
	done := make(chan struct{})
	go func() {
		timeout := time.After(2 * time.Second)
		for {
			select {
			case _, ok := <-fast:
				if !ok {
					close(done)
					return
				}
				fastCount++
				if fastCount >= n {
					close(done)
					return
				}
			case <-timeout:
				close(done)
				return
			}
		}
	}()

	// Measure the elapsed time of the publish loop to prove Log() never
	// blocked on a full subscriber buffer.
	start := time.Now()
	for i := 0; i < n; i++ {
		al.Log(AccessEntry{CallerSpiffeID: "spiffe://t/x", Decision: "allow"})
	}
	publishElapsed := time.Since(start)

	<-done

	if publishElapsed > 500*time.Millisecond {
		t.Errorf("publish loop took %v; fan-out appears to block on slow consumers", publishElapsed)
	}
	if fastCount < n-10 {
		t.Errorf("fast consumer: got %d, want ~%d (concurrent drain should receive nearly all)", fastCount, n)
	}
	// Slow consumer was never read — it must have dropped some entries.
	slowBuffered := len(slow)
	if slowBuffered > 128 {
		t.Errorf("slow consumer buffer has %d entries, exceeds channel capacity 128", slowBuffered)
	}
	if slowBuffered == n {
		t.Errorf("slow consumer got all %d entries despite no reads — fan-out is blocking", n)
	}
}

func TestSubscribeCancelRace(t *testing.T) {
al := NewAccessLogger(100)

// Many producer goroutines publishing continuously.
stop := make(chan struct{})
var wg sync.WaitGroup
for i := 0; i < 4; i++ {
wg.Add(1)
go func() {
defer wg.Done()
for {
select {
case <-stop:
return
default:
al.Log(AccessEntry{CallerSpiffeID: "spiffe://t/x", Decision: "allow"})
}
}
}()
}

// Many subscribers that subscribe then cancel in tight loops.
var subWg sync.WaitGroup
for i := 0; i < 20; i++ {
subWg.Add(1)
go func() {
defer subWg.Done()
for j := 0; j < 100; j++ {
_, cancel := al.Subscribe()
// Let a few entries flow, then cancel.
time.Sleep(time.Microsecond)
cancel()
}
}()
}

subWg.Wait()
close(stop)
wg.Wait()

// If we got here without a panic or a race-detector abort, we're good.
}
