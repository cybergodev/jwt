package internal

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestMemoryStoreConcurrentSaturation drives Add/Contains against a
// concurrently-running Cleanup with maxSize far below the offered key count,
// forcing the cleanupExpiredUnsafe and evictOldestUnsafe paths to execute
// under lock contention. Contract under test (run with -race): no data race,
// no deadlock, and the store keeps serving reads and closes cleanly afterward.
func TestMemoryStoreConcurrentSaturation(t *testing.T) {
	store := NewMemoryStore(8, time.Minute, false, nil)

	const numGoroutines = 16
	const opsPerGoroutine = 200

	var wg sync.WaitGroup
	// One goroutine hammers the explicit cleanup path while the others write.
	wg.Go(func() {
		for range opsPerGoroutine {
			_, _ = store.Cleanup() // stress: best-effort background cleanup
		}
	})

	for g := range numGoroutines {
		wg.Go(func() {
			for j := range opsPerGoroutine {
				tokenID := fmt.Sprintf("sat-%d-%d", g, j)
				_ = store.Add(tokenID, time.Now().Add(time.Hour)) // stress: eviction decides retention
				_, _ = store.Contains(tokenID)                    // stress: result under saturation unspecified
			}
		})
	}
	wg.Wait()

	// Post-conditions: the store still accepts entries and serves reads.
	if err := store.Add("post", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Add after saturation: %v", err)
	}
	if ok, err := store.Contains("post"); err != nil || !ok {
		t.Errorf("Contains after saturation = (%v, %v), want (true, nil)", ok, err)
	}

	// Close cleanly transitions to the closed state exactly once.
	if err := store.Close(); err != nil {
		t.Fatalf("Close after saturation: %v", err)
	}
	if _, err := store.Contains("post"); !errors.Is(err, ErrStoreClosed) {
		t.Errorf("Contains after Close = %v, want ErrStoreClosed", err)
	}
	if err := store.Close(); err != nil {
		t.Errorf("second Close must be a no-op nil, got %v", err)
	}
}
