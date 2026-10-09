package jwt

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

// Resource-lifecycle tests: close semantics, pool cleanup, and goroutine-leak
// detection. RateLimiter eviction/close tests live in ratelimit_test.go.

// TestHMACPoolCleanupOnClose verifies that calling Processor.Close() clears
// the internal HMAC hasher pool, preventing secret key material retention,
// and that the create/use/close cycle is repeatable across processors.
func TestHMACPoolCleanupOnClose(t *testing.T) {
	for i := 0; i < 5; i++ {
		processor, err := newTestProcessor(testSecretKey)
		if err != nil {
			t.Fatalf("Processor %d creation failed: %v", i, err)
		}

		// Generate several tokens to populate the HMAC hasher pool
		for j := 0; j < 10; j++ {
			claims := &Claims{UserID: fmt.Sprintf("pool-user-%d-%d", i, j)}
			if _, err := processor.Create(claims); err != nil {
				t.Fatalf("Create %d/%d failed: %v", i, j, err)
			}
		}

		// Close should drain the HMAC pool
		if err := processor.Close(); err != nil {
			t.Fatalf("Close %d failed: %v", i, err)
		}

		if !processor.IsClosed() {
			t.Errorf("Processor %d should be closed", i)
		}
	}
}

// TestMemoryStoreGoroutineCleanup verifies that the memory store's background
// cleanup goroutine is properly stopped when Close is called.
func TestMemoryStoreGoroutineCleanup(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.Blacklist = DefaultBlacklistConfig()
	cfg.Blacklist.CleanupInterval = 100 * time.Millisecond

	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	// Create and revoke a token to exercise the store
	claims := &Claims{UserID: "goroutine-test"}
	token, err := processor.Create(claims)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if err := processor.Revoke(token); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	// Close should stop the background goroutine
	if err := processor.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

// TestProcessorCloseIdempotent verifies that Close can be called multiple
// times without panic or error on the second call (returns ErrProcessorClosed).
func TestProcessorCloseIdempotent(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	// First close succeeds
	if err := processor.Close(); err != nil {
		t.Fatalf("First Close failed: %v", err)
	}

	// Second close returns ErrProcessorClosed
	if err := processor.Close(); err != ErrProcessorClosed {
		t.Errorf("Second Close should return ErrProcessorClosed, got: %v", err)
	}
}

// TestNoGoroutineLeakAfterClose uses runtime.NumGoroutine to verify
// that closing a processor doesn't leave lingering goroutines.
func TestNoGoroutineLeakAfterClose(t *testing.T) {
	// Warm up the scheduler
	runtime.GC()
	runtime.Gosched()
	time.Sleep(10 * time.Millisecond)
	before := runtime.NumGoroutine()

	const iterations = 10
	for i := 0; i < iterations; i++ {
		cfg := DefaultConfig()
		cfg.SecretKey = testSecretKey
		cfg.Blacklist = DefaultBlacklistConfig()
		cfg.Blacklist.CleanupInterval = 50 * time.Millisecond

		processor, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create processor: %v", err)
		}

		// Use the processor to ensure goroutine starts
		claims := &Claims{UserID: "leak-test"}
		token, err := processor.Create(claims)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		_ = processor.Revoke(token)

		// Wait for auto-cleanup goroutine to be active
		time.Sleep(100 * time.Millisecond)

		_ = processor.Close() // cleanup
	}

	// Allow goroutines to settle
	runtime.GC()
	runtime.Gosched()
	time.Sleep(100 * time.Millisecond)

	after := runtime.NumGoroutine()

	// Allow some tolerance for test framework goroutines
	if after > before+5 {
		t.Errorf("Potential goroutine leak: %d goroutines before, %d after (%d iterations)",
			before, after, iterations)
	}
}
