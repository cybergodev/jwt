package blacklist

import (
	"testing"
	"time"
)

func TestMemoryStoreBasicOperations(t *testing.T) {
	store := NewMemoryStore(100, time.Minute, false)
	defer store.Close()

	tokenID := "test-token-123"
	expiresAt := time.Now().Add(time.Hour)

	// Test Add
	err := store.Add(tokenID, expiresAt)
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Test Contains
	exists, err := store.Contains(tokenID)
	if err != nil {
		t.Fatalf("Contains failed: %v", err)
	}
	if !exists {
		t.Error("Token should exist in store")
	}

	// Test non-existent token
	exists, err = store.Contains("non-existent")
	if err != nil {
		t.Fatalf("Contains failed: %v", err)
	}
	if exists {
		t.Error("Non-existent token should not be found")
	}
}

func TestMemoryStoreExpiration(t *testing.T) {
	store := NewMemoryStore(100, time.Minute, false)
	defer store.Close()

	tokenID := "expired-token"
	expiresAt := time.Now().Add(-time.Hour) // Already expired

	err := store.Add(tokenID, expiresAt)
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Expired token should not be found
	exists, err := store.Contains(tokenID)
	if err != nil {
		t.Fatalf("Contains failed: %v", err)
	}
	if exists {
		t.Error("Expired token should not be found")
	}
}

func TestMemoryStoreCleanup(t *testing.T) {
	store := NewMemoryStore(100, time.Minute, false)
	defer store.Close()

	// Add expired tokens
	for i := 0; i < 5; i++ {
		tokenID := "expired-" + string(rune('0'+i))
		expiresAt := time.Now().Add(-time.Hour)
		store.Add(tokenID, expiresAt)
	}

	// Add valid tokens
	for i := 0; i < 3; i++ {
		tokenID := "valid-" + string(rune('0'+i))
		expiresAt := time.Now().Add(time.Hour)
		store.Add(tokenID, expiresAt)
	}

	// Run cleanup
	cleaned, err := store.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	if cleaned != 5 {
		t.Errorf("Expected 5 tokens cleaned, got %d", cleaned)
	}
}

func TestMemoryStoreMaxSize(t *testing.T) {
	maxSize := 10
	store := NewMemoryStore(maxSize, time.Minute, false)
	defer store.Close()

	// Add more tokens than max size
	for i := 0; i < maxSize+5; i++ {
		tokenID := "token-" + string(rune('0'+i))
		expiresAt := time.Now().Add(time.Hour)
		err := store.Add(tokenID, expiresAt)
		if err != nil {
			t.Fatalf("Add failed: %v", err)
		}
	}

	// Store should handle overflow gracefully
	ms := store.(*memoryStore)
	ms.mu.RLock()
	size := len(ms.tokens)
	ms.mu.RUnlock()

	if size > maxSize {
		t.Errorf("Store size %d exceeds max size %d", size, maxSize)
	}
}

func TestMemoryStoreAutoCleanup(t *testing.T) {
	store := NewMemoryStore(100, 50*time.Millisecond, true)
	defer store.Close()

	// Add expired token
	tokenID := "auto-cleanup-token"
	expiresAt := time.Now().Add(-time.Hour)
	store.Add(tokenID, expiresAt)

	// Wait for auto cleanup
	time.Sleep(100 * time.Millisecond)

	// Token should be cleaned up
	ms := store.(*memoryStore)
	ms.mu.RLock()
	_, exists := ms.tokens[tokenID]
	ms.mu.RUnlock()

	if exists {
		t.Error("Expired token should have been auto-cleaned")
	}
}

func TestMemoryStoreClose(t *testing.T) {
	store := NewMemoryStore(100, time.Minute, true)

	tokenID := "test-token"
	expiresAt := time.Now().Add(time.Hour)
	store.Add(tokenID, expiresAt)

	// Close store
	err := store.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Operations after close should fail
	err = store.Add("new-token", time.Now().Add(time.Hour))
	if err != errStoreClosed {
		t.Errorf("Expected errStoreClosed, got %v", err)
	}

	_, err = store.Contains(tokenID)
	if err != errStoreClosed {
		t.Errorf("Expected errStoreClosed, got %v", err)
	}

	_, err = store.Cleanup()
	if err != errStoreClosed {
		t.Errorf("Expected errStoreClosed, got %v", err)
	}

	// Double close should be safe
	err = store.Close()
	if err != nil {
		t.Errorf("Double close should not error: %v", err)
	}
}

func TestManagerBlacklistToken(t *testing.T) {
	store := NewMemoryStore(100, time.Minute, false)
	defer store.Close()

	manager := NewManager(store)

	tokenID := "test-token-id"
	expiresAt := time.Now().Add(time.Hour)

	err := manager.BlacklistToken(tokenID, expiresAt)
	if err != nil {
		t.Fatalf("BlacklistToken failed: %v", err)
	}

	isBlacklisted, err := manager.IsBlacklisted(tokenID)
	if err != nil {
		t.Fatalf("IsBlacklisted failed: %v", err)
	}
	if !isBlacklisted {
		t.Error("Token should be blacklisted")
	}
}

func TestManagerEmptyTokenID(t *testing.T) {
	store := NewMemoryStore(100, time.Minute, false)
	defer store.Close()

	manager := NewManager(store)

	err := manager.BlacklistToken("", time.Now().Add(time.Hour))
	if err == nil {
		t.Error("Expected error for empty token ID")
	}

	isBlacklisted, err := manager.IsBlacklisted("")
	if err != nil {
		t.Fatalf("IsBlacklisted failed: %v", err)
	}
	if isBlacklisted {
		t.Error("Empty token ID should not be blacklisted")
	}
}

func TestManagerClose(t *testing.T) {
	store := NewMemoryStore(100, time.Minute, false)
	manager := NewManager(store)

	err := manager.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestNewStore(t *testing.T) {
	config := Config{
		CleanupInterval:   time.Minute,
		MaxSize:           100,
		EnableAutoCleanup: true,
	}

	store := NewStore(config)
	if store == nil {
		t.Fatal("NewStore returned nil")
	}
	defer store.Close()

	// Verify store works
	err := store.Add("test", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Store Add failed: %v", err)
	}
}

func TestMemoryStoreConcurrency(t *testing.T) {
	store := NewMemoryStore(1000, time.Minute, false)
	defer store.Close()

	done := make(chan bool)
	numGoroutines := 10
	tokensPerGoroutine := 100

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < tokensPerGoroutine; j++ {
				tokenID := string(rune('a'+id)) + "-" + string(rune('0'+j))
				expiresAt := time.Now().Add(time.Hour)
				store.Add(tokenID, expiresAt)
				store.Contains(tokenID)
			}
			done <- true
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify some tokens exist
	exists, err := store.Contains("a-0")
	if err != nil {
		t.Fatalf("Contains failed: %v", err)
	}
	if !exists {
		t.Error("Expected token to exist after concurrent operations")
	}
}
