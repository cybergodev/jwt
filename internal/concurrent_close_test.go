package internal

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestMemoryStoreCloseRacesCleanup stresses the three-phase Close against the
// auto-cleanup goroutine and concurrent readers/writers: Close (a) flags
// closed and closes stopCleanup under mu, (b) waits for the cleanup goroutine
// outside the lock, and (c) re-locks to clear the map. A cleanup pass already
// inside Cleanup() when Close arrives must neither deadlock Close nor observe
// a nil map. The 1ms interval makes ticks fire throughout the race window,
// and the small maxSize exercises the eviction path concurrently. Errors from
// workers that lose the race with Close (ErrStoreClosed) are the point of the
// test, not failures.
func TestMemoryStoreCloseRacesCleanup(t *testing.T) {
	const iterations = 20
	const workers = 8
	const opsPerWorker = 100

	for iter := range iterations {
		store := NewMemoryStore(64, time.Millisecond, true, nil)

		var wg sync.WaitGroup
		wg.Add(workers + 1)

		for w := range workers {
			go func(id int) {
				defer wg.Done()
				for j := range opsPerWorker {
					tokenID := fmt.Sprintf("race-%d-%d-%d", iter, id, j)
					_ = store.Add(tokenID, time.Now().Add(time.Minute)) // loser gets ErrStoreClosed
					_, _ = store.Contains(tokenID)                      // loser gets ErrStoreClosed
				}
			}(w)
		}

		go func() {
			defer wg.Done()
			time.Sleep(200 * time.Microsecond) // land inside the worker burst
			if err := store.Close(); err != nil {
				t.Errorf("iteration %d: Close failed under load: %v", iter, err)
			}
		}()

		wg.Wait()

		// Once Close returns, the cleanup goroutine must have exited and every
		// subsequent operation must report ErrStoreClosed — never a panic from
		// a nil map.
		if err := store.Add("post-close", time.Now().Add(time.Minute)); err != ErrStoreClosed {
			t.Fatalf("iteration %d: Add after Close: want ErrStoreClosed, got %v", iter, err)
		}
		if _, err := store.Contains("post-close"); err != ErrStoreClosed {
			t.Fatalf("iteration %d: Contains after Close: want ErrStoreClosed, got %v", iter, err)
		}
	}
}

// TestHMACPoolDrainConcurrent covers the multi-processor Close scenario:
// Processor.Close drains the package-global HMAC pools while other processors
// sign and verify through the same pools. Get/Put/drain must interleave safely
// (a Get removes the entry, so a drained entry is never concurrently in use),
// and entries rebuilt after a drain must still verify. Two distinct keys force
// the key-mismatch rebuild path in getHasher to run against the drainer.
func TestHMACPoolDrainConcurrent(t *testing.T) {
	method, err := GetInternalSigningMethod("HS256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod failed: %v", err)
	}

	keyA := []byte("concurrent-key-A-with-sufficient-length")
	keyB := []byte("concurrent-key-B-with-sufficient-length")
	signingString := "test.data"

	const ops = 300
	var wg sync.WaitGroup
	wg.Add(3)

	sign := func(key []byte, label string) {
		defer wg.Done()
		for range ops {
			sig, err := method.Sign(signingString, key)
			if err != nil {
				t.Errorf("%s: Sign failed under concurrent drain: %v", label, err)
				return
			}
			if err := method.Verify(signingString, sig, key); err != nil {
				t.Errorf("%s: Verify failed after concurrent drain: %v", label, err)
				return
			}
		}
	}
	go sign(keyA, "keyA")
	go sign(keyB, "keyB")

	go func() {
		defer wg.Done()
		for range ops {
			ClearHMACCaches()
			runtime.Gosched() // yield so signers interleave with the drain
		}
	}()

	wg.Wait()
}
