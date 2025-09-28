package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cybergodev/jwt/internal/blacklist"
	"github.com/cybergodev/jwt/internal/core"
	"github.com/cybergodev/jwt/internal/security"
	"github.com/cybergodev/jwt/internal/signing"
)

// 🧪 COMPREHENSIVE INTERNAL TESTS: Internal Components Testing

func TestSecureBytes(t *testing.T) {
	// Test SecureBytes creation and cleanup
	data := []byte("test-secret-key-data-12345678901234567890")
	secureBytes := security.NewSecureBytesFromSlice(data)

	if secureBytes == nil {
		t.Fatal("SecureBytes should not be nil")
	}

	// Test that bytes are accessible
	retrievedBytes := secureBytes.Bytes()
	if len(retrievedBytes) != len(data) {
		t.Errorf("Expected %d bytes, got %d", len(data), len(retrievedBytes))
	}

	for i, b := range data {
		if retrievedBytes[i] != b {
			t.Errorf("Byte mismatch at index %d: expected %d, got %d", i, b, retrievedBytes[i])
		}
	}

	// Test cleanup
	secureBytes.Destroy()

	// After cleanup, bytes should be zeroed (though we can't easily test this
	// without exposing internal state)
}

func TestWeakKeyDetection(t *testing.T) {
	weakKeys := [][]byte{
		[]byte("password123456789012345678901234"), // Common pattern
		[]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), // All same character
		[]byte("12345678901234567890123456789012"), // Sequential numbers
	}

	for i, key := range weakKeys {
		t.Run(fmt.Sprintf("WeakKey_%d", i), func(t *testing.T) {
			if !security.IsWeakKey(key) {
				t.Errorf("Key should be detected as weak: %s", string(key))
			}
		})
	}

	strongKeys := [][]byte{
		[]byte(testSecretKey),
		[]byte("aB3$fG7*kL9#pQ2&vX5!zC8@mN4%rT6^wY1+eH0-iJ3~oU7$bD9#gK2&sF5*nM8@"),
	}

	for i, key := range strongKeys {
		t.Run(fmt.Sprintf("StrongKey_%d", i), func(t *testing.T) {
			if security.IsWeakKey(key) {
				t.Errorf("Key should not be detected as weak: %s", string(key))
			}
		})
	}
}

func TestSecureCompare(t *testing.T) {
	// Test equal byte slices
	a := []byte("test-data-12345")
	b := []byte("test-data-12345")

	if !security.SecureCompare(a, b) {
		t.Error("Equal byte slices should compare as equal")
	}

	// Test different byte slices
	c := []byte("test-data-54321")
	if security.SecureCompare(a, c) {
		t.Error("Different byte slices should compare as not equal")
	}

	// Test different lengths
	d := []byte("test-data-12345-extra")
	if security.SecureCompare(a, d) {
		t.Error("Different length byte slices should compare as not equal")
	}

	// Test empty slices
	empty1 := []byte{}
	empty2 := []byte{}
	if !security.SecureCompare(empty1, empty2) {
		t.Error("Empty byte slices should compare as equal")
	}

	// Test nil slices
	if !security.SecureCompare(nil, nil) {
		t.Error("Nil byte slices should compare as equal")
	}

	if !security.SecureCompare(nil, empty1) {
		t.Error("Nil and empty slices should compare as equal")
	}
}

func TestCoreTokenParsing(t *testing.T) {
	// Create a valid token first
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Test parsing with core package
	parsedClaims := &Claims{}
	coreToken, err := core.ParseWithClaims(token, parsedClaims, func(token *core.Core) (any, error) {
		return []byte(testSecretKey), nil
	})

	if err != nil {
		t.Fatalf("Failed to parse token with core: %v", err)
	}

	if coreToken == nil {
		t.Fatal("Parsed token should not be nil")
	}

	if !coreToken.Valid {
		t.Error("Parsed token should be valid")
	}

	if parsedClaims.UserID != claims.UserID {
		t.Errorf("Expected UserID=%s, got UserID=%s", claims.UserID, parsedClaims.UserID)
	}
}

func TestSigningMethods(t *testing.T) {
	methods := map[string]signing.Method{
		"HS256": signing.GetHMACMethod("HS256"),
		"HS384": signing.GetHMACMethod("HS384"),
		"HS512": signing.GetHMACMethod("HS512"),
	}

	testData := "test-signing-string"
	key := []byte(testSecretKey)

	for name, method := range methods {
		if method == nil {
			t.Errorf("Signing method %s should not be nil", name)
			continue
		}

		t.Run(name, func(t *testing.T) {
			// Test algorithm name
			if method.Alg() != name {
				t.Errorf("Expected algorithm %s, got %s", name, method.Alg())
			}

			// Test signing
			signature, err := method.Sign(testData, key)
			if err != nil {
				t.Fatalf("Failed to sign with %s: %v", name, err)
			}

			if signature == "" {
				t.Errorf("Signature should not be empty for %s", name)
			}

			// Test verification
			err = method.Verify(testData, signature, key)
			if err != nil {
				t.Errorf("Failed to verify signature with %s: %v", name, err)
			}

			// Test verification with wrong key
			wrongKey := []byte("wrong-key-12345678901234567890123456")
			err = method.Verify(testData, signature, wrongKey)
			if err == nil {
				t.Errorf("Should fail to verify with wrong key for %s", name)
			}

			// Test verification with wrong signature
			err = method.Verify(testData, "wrong-signature", key)
			if err == nil {
				t.Errorf("Should fail to verify with wrong signature for %s", name)
			}
		})
	}
}

func TestBlacklistMemoryStore(t *testing.T) {
	store := blacklist.NewMemoryStore(1000)
	if store == nil {
		t.Fatal("Memory store should not be nil")
	}

	tokenID := "test-token-id-123"
	expiresAt := time.Now().Add(1 * time.Hour)

	// Test adding token
	err := store.Add(tokenID, expiresAt)
	if err != nil {
		t.Fatalf("Failed to add token to store: %v", err)
	}

	// Test checking if token exists
	exists, err := store.Contains(tokenID)
	if err != nil {
		t.Fatalf("Failed to check token in store: %v", err)
	}
	if !exists {
		t.Error("Token should exist in store")
	}

	// Test checking non-existent token
	exists, err = store.Contains("non-existent-token")
	if err != nil {
		t.Fatalf("Failed to check non-existent token: %v", err)
	}
	if exists {
		t.Error("Non-existent token should not exist in store")
	}

	// Test removing token
	err = store.Remove(tokenID)
	if err != nil {
		t.Fatalf("Failed to remove token from store: %v", err)
	}

	// Token should no longer exist
	exists, err = store.Contains(tokenID)
	if err != nil {
		t.Fatalf("Failed to check removed token: %v", err)
	}
	if exists {
		t.Error("Removed token should not exist in store")
	}

	// Test store size
	size, err := store.Size()
	if err != nil {
		t.Fatalf("Failed to get store size: %v", err)
	}
	if size != 0 {
		t.Errorf("Expected store size 0, got %d", size)
	}

	// Add multiple tokens
	for i := 0; i < 5; i++ {
		err = store.Add(fmt.Sprintf("token-%d", i), expiresAt)
		if err != nil {
			t.Fatalf("Failed to add token %d: %v", i, err)
		}
	}

	size, err = store.Size()
	if err != nil {
		t.Fatalf("Failed to get store size: %v", err)
	}
	if size != 5 {
		t.Errorf("Expected store size 5, got %d", size)
	}

	// Test cleanup
	_, err = store.Cleanup()
	if err != nil {
		t.Fatalf("Failed to cleanup store: %v", err)
	}

	// Size should remain the same since tokens haven't expired
	size, err = store.Size()
	if err != nil {
		t.Fatalf("Failed to get store size after cleanup: %v", err)
	}
	if size != 5 {
		t.Errorf("Expected store size 5 after cleanup, got %d", size)
	}

	// Add expired token and cleanup
	expiredTokenID := "expired-token"
	expiredTime := time.Now().Add(-1 * time.Hour)
	err = store.Add(expiredTokenID, expiredTime)
	if err != nil {
		t.Fatalf("Failed to add expired token: %v", err)
	}

	_, err = store.Cleanup()
	if err != nil {
		t.Fatalf("Failed to cleanup expired tokens: %v", err)
	}

	// Expired token should be removed
	exists, err = store.Contains(expiredTokenID)
	if err != nil {
		t.Fatalf("Failed to check expired token: %v", err)
	}
	if exists {
		t.Error("Expired token should be removed after cleanup")
	}
}

func TestCoreDecodeSegment(t *testing.T) {
	// Test valid base64url encoding
	data := map[string]any{
		"test": "value",
		"num":  123,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(jsonData)

	var decoded map[string]any
	err = core.DecodeSegment(encoded, &decoded)
	if err != nil {
		t.Fatalf("Failed to decode valid segment: %v", err)
	}

	if decoded["test"] != "value" {
		t.Errorf("Expected test=value, got test=%v", decoded["test"])
	}

	// Test invalid base64url
	err = core.DecodeSegment("invalid-base64!", &decoded)
	if err == nil {
		t.Error("Should fail to decode invalid base64url")
	}

	// Test empty segment
	err = core.DecodeSegment("", &decoded)
	if err == nil {
		t.Error("Should fail to decode empty segment")
	}

	// Test extremely long segment
	longSegment := strings.Repeat("a", 10000)
	err = core.DecodeSegment(longSegment, &decoded)
	if err == nil {
		t.Error("Should fail to decode extremely long segment")
	}
}

func TestRandomDelay(t *testing.T) {
	// Test that RandomDelay doesn't panic and takes some time
	start := time.Now()
	security.RandomDelay()
	duration := time.Since(start)

	// Should take at least some time (but not too much for tests)
	if duration < 1*time.Microsecond {
		t.Error("RandomDelay should take some time")
	}
	if duration > 100*time.Millisecond {
		t.Error("RandomDelay should not take too long")
	}
}

func TestClaimsPool(t *testing.T) {
	// Test claims pool functionality
	claims1 := getClaims()
	if claims1 == nil {
		t.Fatal("getClaims should return non-nil claims")
	}

	claims1.UserID = "test-user"
	claims1.Username = "test-username"

	// Return to pool
	putClaims(claims1)

	// Get another claims object (might be the same one from pool)
	claims2 := getClaims()
	if claims2 == nil {
		t.Fatal("getClaims should return non-nil claims after put")
	}

	// Claims should be reset
	if claims2.UserID != "" {
		t.Error("Claims from pool should be reset")
	}
	if claims2.Username != "" {
		t.Error("Claims from pool should be reset")
	}

	putClaims(claims2)
}
