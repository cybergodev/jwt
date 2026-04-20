package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// HMAC Signing Method Tests
// =============================================================================

func TestHMACSignAndVerify(t *testing.T) {
	key := []byte("test-secret-key-with-sufficient-length")
	signingString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0"

	tests := []struct {
		alg string
	}{
		{"HS256"},
		{"HS384"},
		{"HS512"},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			method, err := GetInternalSigningMethod(tt.alg)
			if err != nil {
				t.Fatalf("GetInternalSigningMethod(%q) failed: %v", tt.alg, err)
			}
			if method == nil {
				t.Fatalf("GetInternalSigningMethod(%q) returned nil", tt.alg)
			}

			if !method.Hash().Available() {
				t.Skipf("Hash function %v not available on this platform", method.Hash())
			}

			// Sign
			signature, err := method.Sign(signingString, key)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
			if signature == "" {
				t.Error("Sign returned empty signature")
			}

			// Verify with correct signature
			err = method.Verify(signingString, signature, key)
			if err != nil {
				t.Errorf("Verify failed: %v", err)
			}

			// Verify with wrong signature
			wrongSignature := "invalid-signature"
			err = method.Verify(signingString, wrongSignature, key)
			if err == nil {
				t.Error("Expected error for invalid signature, got nil")
			}

			// Verify with wrong key
			wrongKey := []byte("wrong-key-different-from-original")
			err = method.Verify(signingString, signature, wrongKey)
			if err == nil {
				t.Error("Expected error for wrong key, got nil")
			}
		})
	}
}

func TestHMACInvalidKey(t *testing.T) {
	method, err := GetInternalSigningMethod("HS256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod failed: %v", err)
	}
	signingString := "test.data"

	// Test Sign with non-[]byte key
	_, err = method.Sign(signingString, "string-key")
	if err == nil {
		t.Error("Expected error for non-[]byte key in Sign, got nil")
	}
	if !strings.Contains(err.Error(), "must be []byte") {
		t.Errorf("Expected 'must be []byte' in error, got: %v", err)
	}

	// Test Verify with non-[]byte key
	err = method.Verify(signingString, "signature", "string-key")
	if err == nil {
		t.Error("Expected error for non-[]byte key in Verify, got nil")
	}
	if !strings.Contains(err.Error(), "must be []byte") {
		t.Errorf("Expected 'must be []byte' in error, got: %v", err)
	}

	// Test Verify with invalid base64 signature
	key := []byte("test-secret-key")
	err = method.Verify(signingString, "!!!invalid-base64!!!", key)
	if err == nil {
		t.Error("Expected error for invalid base64 signature, got nil")
	}
}

func TestSignedString(t *testing.T) {
	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	}
	claims := map[string]any{
		"sub": "user123",
		"exp": 1234567890,
	}
	method, err := GetInternalSigningMethod("HS256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod failed: %v", err)
	}
	key := []byte("test-secret-key-with-sufficient-length")

	tokenString, err := SignedString(header, claims, method, key)
	if err != nil {
		t.Fatalf("SignedString failed: %v", err)
	}

	if tokenString == "" {
		t.Error("SignedString returned empty string")
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		t.Errorf("Expected 3 parts, got %d", len(parts))
	}

	// Test with invalid header (non-serializable)
	invalidHeader := map[string]any{
		"alg":     "HS256",
		"invalid": make(chan int),
	}
	_, err = SignedString(invalidHeader, claims, method, key)
	if err == nil {
		t.Error("Expected error for invalid header, got nil")
	}

	// Test with invalid claims (non-serializable)
	invalidClaims := map[string]any{
		"sub":     "test",
		"invalid": make(chan int),
	}
	_, err = SignedString(header, invalidClaims, method, key)
	if err == nil {
		t.Error("Expected error for invalid claims, got nil")
	}
}

func TestGetInternalSigningMethod(t *testing.T) {
	tests := []struct {
		alg     string
		wantErr bool
	}{
		// HMAC methods
		{"HS256", false},
		{"HS384", false},
		{"HS512", false},
		// RSA methods
		{"RS256", false},
		{"RS384", false},
		{"RS512", false},
		// ECDSA methods
		{"ES256", false},
		{"ES384", false},
		{"ES512", false},
		// Invalid/unsupported methods
		{"", true},
		{"none", true},
		{"invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			method, err := GetInternalSigningMethod(tt.alg)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetInternalSigningMethod(%q) error = %v, wantErr %v", tt.alg, err, tt.wantErr)
			}
			if !tt.wantErr && method == nil {
				t.Error("Expected method, got nil")
			}
			if tt.wantErr && method != nil {
				t.Error("Expected nil method for error case")
			}
		})
	}
}

// =============================================================================
// Core Token Tests
// =============================================================================

func TestNewTokenWithClaims(t *testing.T) {
	method, err := GetInternalSigningMethod("HS256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod failed: %v", err)
	}
	claims := map[string]any{
		"sub": "user123",
		"exp": 1234567890,
	}

	token := NewTokenWithClaims(method, claims)
	if token == nil {
		t.Fatal("NewTokenWithClaims returned nil")
	}

	if token.Header["typ"] != "JWT" {
		t.Errorf("Expected typ=JWT, got %v", token.Header["typ"])
	}

	if token.Header["alg"] != "HS256" {
		t.Errorf("Expected alg=HS256, got %v", token.Header["alg"])
	}

	if token.Claims == nil {
		t.Error("Claims not set correctly")
	}

	if token.Method != method {
		t.Error("Method not set correctly")
	}
}

func TestCoreSignedString(t *testing.T) {
	method, err := GetInternalSigningMethod("HS256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod failed: %v", err)
	}
	claims := map[string]any{
		"sub": "user123",
		"exp": 1234567890,
	}

	token := NewTokenWithClaims(method, claims)
	key := []byte("test-secret-key-with-sufficient-length-32bytes")

	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString failed: %v", err)
	}

	if tokenString == "" {
		t.Error("SignedString returned empty string")
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		t.Errorf("Expected 3 parts, got %d", len(parts))
	}
}

func TestGenerateTokenID(t *testing.T) {
	id1, err := GenerateTokenID()
	if err != nil {
		t.Fatalf("GenerateTokenID failed: %v", err)
	}

	if len(id1) != 4+TokenIDLength*2 {
		t.Errorf("Expected length %d, got %d", 4+TokenIDLength*2, len(id1))
	}

	if !strings.HasPrefix(id1, "tok_") {
		t.Errorf("Expected prefix 'tok_', got %q", id1[:4])
	}

	id2, err := GenerateTokenID()
	if err != nil {
		t.Fatalf("GenerateTokenID failed: %v", err)
	}
	if id1 == id2 {
		t.Error("Generated IDs should be unique")
	}

	// Test uniqueness with 100 IDs
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := GenerateTokenID()
		if err != nil {
			t.Fatalf("GenerateTokenID failed: %v", err)
		}
		if ids[id] {
			t.Errorf("Duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}

// =============================================================================
// Parser Tests
// =============================================================================

func TestFastSplit3(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		sep    byte
		wantP1 string
		wantP2 string
		wantP3 string
		wantOk bool
	}{
		{
			name:   "valid JWT format",
			input:  "header.payload.signature",
			sep:    '.',
			wantP1: "header",
			wantP2: "payload",
			wantP3: "signature",
			wantOk: true,
		},
		{
			name:   "only one separator",
			input:  "header.payload",
			sep:    '.',
			wantOk: false,
		},
		{
			name:   "no separator",
			input:  "headerPayloadSignature",
			sep:    '.',
			wantOk: false,
		},
		{
			name:   "empty string",
			input:  "",
			sep:    '.',
			wantOk: false,
		},
		{
			name:   "extra separators",
			input:  "a.b.c.d",
			sep:    '.',
			wantP1: "a",
			wantP2: "b",
			wantP3: "c.d",
			wantOk: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p1, p2, p3, ok := fastSplit3(tt.input, tt.sep)
			if ok != tt.wantOk {
				t.Errorf("fastSplit3() ok = %v, want %v", ok, tt.wantOk)
			}
			if ok && (p1 != tt.wantP1 || p2 != tt.wantP2 || p3 != tt.wantP3) {
				t.Errorf("fastSplit3() = (%q, %q, %q), want (%q, %q, %q)",
					p1, p2, p3, tt.wantP1, tt.wantP2, tt.wantP3)
			}
		})
	}
}

func TestIsInsecureAlgorithm(t *testing.T) {
	tests := []struct {
		alg        string
		wantSecure bool
	}{
		{"", true},
		{"none", true},
		{"NONE", true},
		{"None", true},
		{"HS1", true},
		{"RS1", true},
		{"ES1", true},
		{"HS224", true},
		{"RS224", true},
		{"ES224", true},
		{"NULL", true},
		{"null", true},
		{"PLAIN", true},
		{"plain", true},
		{"HS256", false},
		{"HS384", false},
		{"HS512", false},
		{"  none  ", true},
		{"  HS256  ", false},
		{"  NONE  ", true},
		{"  null  ", true},
		{"  PLAIN  ", true},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			result := isInsecureAlgorithm(tt.alg)
			if result != tt.wantSecure {
				t.Errorf("isInsecureAlgorithm(%q) = %v, want %v", tt.alg, result, tt.wantSecure)
			}
		})
	}
}

func TestParseWithClaimsErrors(t *testing.T) {
	tests := []struct {
		name        string
		tokenString string
		wantErr     string
	}{
		{
			name:        "empty token",
			tokenString: "",
			wantErr:     "empty token",
		},
		{
			name:        "token too large",
			tokenString: strings.Repeat("a", 9000),
			wantErr:     "token too large",
		},
		{
			name:        "invalid format - no dots",
			tokenString: "invalidtoken",
			wantErr:     "invalid token format",
		},
		{
			name:        "invalid format - one dot",
			tokenString: "header.payload",
			wantErr:     "invalid token format",
		},
		{
			name:        "part too large",
			tokenString: strings.Repeat("a", 5000) + "." + "b" + "." + "c",
			wantErr:     "segment too large",
		},
		{
			name:        "invalid header encoding",
			tokenString: "!!!invalid!!!.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantErr:     "failed to decode header",
		},
		{
			name:        "missing algorithm",
			tokenString: "eyJ0eXAiOiJKV1QifQ.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantErr:     "algorithm",
		},
		{
			name:        "empty algorithm",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiIifQ.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantErr:     "algorithm",
		},
		{
			name:        "insecure algorithm - NONE",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJOT05FIn0.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantErr:     "insecure algorithm",
		},
		{
			name:        "insecure algorithm - NULL",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJOVUxMIn0.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantErr:     "insecure algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := make(map[string]any)
			keyFunc := func(*Core) (any, error) {
				return []byte("test-secret-key"), nil
			}

			_, err := ParseWithClaims(tt.tokenString, claims, keyFunc)
			if err == nil {
				t.Error("Expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestParseWithClaimsKeyFuncError(t *testing.T) {
	// Create a valid token first
	method, err := GetInternalSigningMethod("HS256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod failed: %v", err)
	}
	claims := map[string]any{
		"user_id": "test",
	}
	token := NewTokenWithClaims(method, claims)
	key := []byte("test-secret-key-with-sufficient-length-32bytes")
	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Parse with key function that returns error
	keyFunc := func(token *Core) (any, error) {
		return nil, &testError{msg: "test key function error"}
	}

	parsedClaims := make(map[string]any)
	_, err = ParseWithClaims(tokenString, &parsedClaims, keyFunc)
	if err == nil {
		t.Error("Expected error from key function")
	}
	if !strings.Contains(err.Error(), "failed to get key") {
		t.Errorf("Expected 'failed to get key' error, got %v", err)
	}
}

func TestParseWithClaimsInvalidSignature(t *testing.T) {
	// Create a valid token
	method, err := GetInternalSigningMethod("HS256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod failed: %v", err)
	}
	claims := map[string]any{
		"user_id": "test",
	}
	token := NewTokenWithClaims(method, claims)
	key := []byte("test-secret-key-with-sufficient-length-32bytes")
	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Parse with different key (signature verification should fail)
	wrongKey := []byte("wrong-secret-key-with-sufficient-length-32bytes")
	keyFunc := func(token *Core) (any, error) {
		return wrongKey, nil
	}

	parsedClaims := make(map[string]any)
	parsedToken, err := ParseWithClaims(tokenString, &parsedClaims, keyFunc)
	if err != nil {
		t.Fatalf("Parse should not return error, got %v", err)
	}

	if parsedToken.Valid {
		t.Error("Token should not be valid with wrong key")
	}
}

func TestParseUnverifiedErrors(t *testing.T) {
	tests := []struct {
		name        string
		tokenString string
		wantErr     string
	}{
		{
			name:        "empty token",
			tokenString: "",
			wantErr:     "empty token",
		},
		{
			name:        "token too large",
			tokenString: strings.Repeat("a", 9000),
			wantErr:     "token too large",
		},
		{
			name:        "invalid format",
			tokenString: "invalid",
			wantErr:     "invalid token format",
		},
		{
			name:        "invalid header",
			tokenString: "!!!invalid!!!.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantErr:     "failed to decode header",
		},
		{
			name:        "insecure algorithm in header",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJOT05FIn0.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantErr:     "insecure algorithm detected",
		},
		{
			name:        "invalid claims",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.!!!invalid!!!.signature",
			wantErr:     "failed to decode claims",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := make(map[string]any)
			_, _, err := ParseUnverified(tt.tokenString, claims)
			if err == nil {
				t.Error("Expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

// =============================================================================
// Encoding Tests
// =============================================================================

func TestDecodeSegmentErrors(t *testing.T) {
	tests := []struct {
		name    string
		segment string
		wantErr bool
	}{
		{
			name:    "empty segment",
			segment: "",
			wantErr: true,
		},
		{
			name:    "segment too large",
			segment: strings.Repeat("a", 5000),
			wantErr: true,
		},
		{
			name:    "invalid base64",
			segment: "!!!invalid!!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dest map[string]any
			err := DecodeSegment(tt.segment, &dest)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeSegment() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// Security Tests
// =============================================================================

func TestIsWeakKey(t *testing.T) {
	weakKeys := [][]byte{
		[]byte("password123456789012345678901234"),
		[]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		[]byte("12345678901234567890123456789012"),
		[]byte("qwertyuiopasdfghjklzxcvbnm123456"),
		[]byte{}, // empty key
		[]byte("abcdefghijklmnopqrstuvwxyz123456"),   // sequential
		[]byte("ababababababababababababababababab"), // low entropy
	}

	for i, key := range weakKeys {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			if !IsWeakKey(key) {
				t.Errorf("Key should be detected as weak: %s", string(key))
			}
		})
	}

	strongKeys := [][]byte{
		[]byte("Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"),
		[]byte("aB3$fG7*kL9#pQ2&vX5!zC8@mN4%rT6^wY1+eH0-iJ3~oU7$bD9#gK2&sF5*nM8@"),
	}

	for i, key := range strongKeys {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			if IsWeakKey(key) {
				t.Errorf("Key should not be detected as weak: %s", string(key))
			}
		})
	}
}

func TestZeroBytes(t *testing.T) {
	data := []byte("sensitive-data-to-zero")

	ZeroBytes(data)

	// Check that data has been zeroed
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}

	if !allZero {
		t.Error("ZeroBytes should zero all bytes")
	}
}

// =============================================================================
// Memory Store Tests
// =============================================================================

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

// =============================================================================
// Manager Tests
// =============================================================================

func TestManagerBlacklistToken(t *testing.T) {
	store := NewMemoryStore(1000, 5*time.Minute, false)
	defer store.Close()

	manager := NewManager(store)

	// Test with empty token ID
	err := manager.BlacklistToken("", time.Now().Add(time.Hour))
	if err == nil {
		t.Error("Expected error for empty token ID")
	}
	if !strings.Contains(err.Error(), "token ID cannot be empty") {
		t.Errorf("Expected 'token ID cannot be empty' error, got %v", err)
	}

	// Test with valid token ID
	tokenID := "tok_valid123"
	expiresAt := time.Now().Add(time.Hour)
	err = manager.BlacklistToken(tokenID, expiresAt)
	if err != nil {
		t.Fatalf("BlacklistToken failed: %v", err)
	}

	// Verify token is blacklisted
	isBlacklisted, err := manager.IsBlacklisted(tokenID)
	if err != nil {
		t.Fatalf("IsBlacklisted failed: %v", err)
	}
	if !isBlacklisted {
		t.Error("Token should be blacklisted")
	}
}

func TestManagerIsBlacklisted(t *testing.T) {
	store := NewMemoryStore(1000, 5*time.Minute, false)
	manager := NewManager(store)
	defer manager.Close()

	// Test with empty token ID
	isBlacklisted, err := manager.IsBlacklisted("")
	if err != nil {
		t.Errorf("Expected no error for empty token ID, got %v", err)
	}
	if isBlacklisted {
		t.Error("Empty token ID should not be blacklisted")
	}

	// Test with non-existent token ID
	isBlacklisted, err = manager.IsBlacklisted("tok_nonexistent")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if isBlacklisted {
		t.Error("Non-existent token should not be blacklisted")
	}
}

func TestManagerBlacklistTokenString(t *testing.T) {
	store := NewMemoryStore(1000, 5*time.Minute, false)
	manager := NewManager(store)
	defer manager.Close()

	tests := []struct {
		name        string
		tokenString string
		wantError   bool
		errorMsg    string
	}{
		{
			name:        "empty token string",
			tokenString: "",
			wantError:   true,
			errorMsg:    "token string cannot be empty",
		},
		{
			name:        "invalid token format",
			tokenString: "invalid",
			wantError:   true,
			errorMsg:    "failed to parse token",
		},
		{
			name:        "token without jti",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantError:   true,
			errorMsg:    "token does not contain a valid ID",
		},
		{
			name:        "valid token with jti and exp",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJ0b2tfMTIzNDU2IiwiZXhwIjoxNzAwMDAwMDAwfQ.signature",
			wantError:   false,
		},
		{
			name:        "valid token with jti without exp",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJ0b2tfNzg5MDEyIn0.signature",
			wantError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.BlacklistTokenString(tt.tokenString)
			if tt.wantError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
			if tt.wantError && err != nil && !strings.Contains(err.Error(), tt.errorMsg) {
				t.Errorf("Expected error containing '%s', got '%v'", tt.errorMsg, err)
			}
		})
	}
}

func TestManagerClose(t *testing.T) {
	store := NewMemoryStore(1000, 5*time.Minute, false)
	manager := NewManager(store)

	// Add some tokens
	err := manager.BlacklistToken("tok_test1", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Failed to blacklist token: %v", err)
	}

	// Close manager
	err = manager.Close()
	if err != nil {
		t.Errorf("Failed to close manager: %v", err)
	}
}

// =============================================================================
// Helper Types
// =============================================================================

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// =============================================================================
// RSA Signing Method Tests
// =============================================================================

func TestRSASignAndVerify(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	signingString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0"

	tests := []struct {
		alg string
	}{
		{"RS256"},
		{"RS384"},
		{"RS512"},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			method, err := GetInternalSigningMethod(tt.alg)
			if err != nil {
				t.Fatalf("GetInternalSigningMethod(%q) failed: %v", tt.alg, err)
			}
			if method == nil {
				t.Fatalf("GetInternalSigningMethod(%q) returned nil", tt.alg)
			}

			// Test algorithm name
			if method.Alg() != tt.alg {
				t.Errorf("Alg() = %q, want %q", method.Alg(), tt.alg)
			}

			// Sign with private key
			signature, err := method.Sign(signingString, privateKey)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
			if signature == "" {
				t.Error("Sign returned empty signature")
			}

			// Verify with public key (from private key)
			err = method.Verify(signingString, signature, privateKey)
			if err != nil {
				t.Errorf("Verify with private key failed: %v", err)
			}

			// Verify with public key
			err = method.Verify(signingString, signature, &privateKey.PublicKey)
			if err != nil {
				t.Errorf("Verify with public key failed: %v", err)
			}

			// Verify with wrong key
			wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			err = method.Verify(signingString, signature, wrongKey)
			if err == nil {
				t.Error("Expected error for wrong key, got nil")
			}

			// Verify with invalid signature
			err = method.Verify(signingString, "invalid-signature", privateKey)
			if err == nil {
				t.Error("Expected error for invalid signature, got nil")
			}
		})
	}
}

func TestRSAInvalidKeyType(t *testing.T) {
	method, err := GetInternalSigningMethod("RS256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod failed: %v", err)
	}

	signingString := "test.data"

	// Test Sign with non-RSA key
	_, err = method.Sign(signingString, "string-key")
	if err == nil {
		t.Error("Expected error for non-RSA key in Sign, got nil")
	}
	if !strings.Contains(err.Error(), "must be *rsa.PrivateKey") {
		t.Errorf("Expected 'must be *rsa.PrivateKey' in error, got: %v", err)
	}

	// Test Verify with non-RSA key
	err = method.Verify(signingString, "signature", "string-key")
	if err == nil {
		t.Error("Expected error for non-RSA key in Verify, got nil")
	}
	if !strings.Contains(err.Error(), "must be *rsa.PublicKey") {
		t.Errorf("Expected 'must be *rsa.PublicKey' in error, got: %v", err)
	}

	// Test Verify with invalid base64 signature
	err = method.Verify(signingString, "!!!invalid-base64!!!", &rsa.PublicKey{})
	if err == nil {
		t.Error("Expected error for invalid base64 signature, got nil")
	}
}

// =============================================================================
// ECDSA Signing Method Tests
// =============================================================================

func TestECDSASignAndVerify(t *testing.T) {
	signingString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0"

	tests := []struct {
		alg   string
		curve elliptic.Curve
	}{
		{"ES256", elliptic.P256()},
		{"ES384", elliptic.P384()},
		{"ES512", elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key: %v", err)
			}

			method, err := GetInternalSigningMethod(tt.alg)
			if err != nil {
				t.Fatalf("GetInternalSigningMethod(%q) failed: %v", tt.alg, err)
			}
			if method == nil {
				t.Fatalf("GetInternalSigningMethod(%q) returned nil", tt.alg)
			}

			// Test algorithm name
			if method.Alg() != tt.alg {
				t.Errorf("Alg() = %q, want %q", method.Alg(), tt.alg)
			}

			// Sign with private key
			signature, err := method.Sign(signingString, privateKey)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
			if signature == "" {
				t.Error("Sign returned empty signature")
			}

			// Verify with private key (extracts public key)
			err = method.Verify(signingString, signature, privateKey)
			if err != nil {
				t.Errorf("Verify with private key failed: %v", err)
			}

			// Verify with public key
			err = method.Verify(signingString, signature, &privateKey.PublicKey)
			if err != nil {
				t.Errorf("Verify with public key failed: %v", err)
			}

			// Verify with wrong key
			wrongKey, _ := ecdsa.GenerateKey(tt.curve, rand.Reader)
			err = method.Verify(signingString, signature, wrongKey)
			if err == nil {
				t.Error("Expected error for wrong key, got nil")
			}

			// Verify with invalid signature length
			err = method.Verify(signingString, "YWJj", privateKey) // "abc" in base64
			if err == nil {
				t.Error("Expected error for invalid signature length, got nil")
			}
		})
	}
}

func TestECDSAInvalidKeyType(t *testing.T) {
	method, err := GetInternalSigningMethod("ES256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod failed: %v", err)
	}

	signingString := "test.data"

	// Test Sign with non-ECDSA key
	_, err = method.Sign(signingString, "string-key")
	if err == nil {
		t.Error("Expected error for non-ECDSA key in Sign, got nil")
	}
	if !strings.Contains(err.Error(), "must be *ecdsa.PrivateKey") {
		t.Errorf("Expected 'must be *ecdsa.PrivateKey' in error, got: %v", err)
	}

	// Test Verify with non-ECDSA key
	err = method.Verify(signingString, "signature", "string-key")
	if err == nil {
		t.Error("Expected error for non-ECDSA key in Verify, got nil")
	}
	if !strings.Contains(err.Error(), "must be *ecdsa.PublicKey") {
		t.Errorf("Expected 'must be *ecdsa.PublicKey' in error, got: %v", err)
	}

	// Test Verify with invalid base64 signature
	err = method.Verify(signingString, "!!!invalid-base64!!!", &ecdsa.PublicKey{})
	if err == nil {
		t.Error("Expected error for invalid base64 signature, got nil")
	}
}

func TestECDSASignatureLength(t *testing.T) {
	method, err := GetInternalSigningMethod("ES256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod failed: %v", err)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Create a valid signature first
	signingString := "test.data"
	validSig, err := method.Sign(signingString, privateKey)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Create a signature with wrong length (decode, truncate, re-encode)
	sigBytes, _ := base64.RawURLEncoding.DecodeString(validSig)
	wrongLenSig := base64.RawURLEncoding.EncodeToString(sigBytes[:10]) // Too short

	err = method.Verify(signingString, wrongLenSig, privateKey)
	if err == nil {
		t.Error("Expected error for wrong signature length, got nil")
	}
}

// =============================================================================
// Hash() Method Coverage Tests
// =============================================================================

func TestSigningMethodHash(t *testing.T) {
	tests := []struct {
		alg string
	}{
		{"HS256"}, {"HS384"}, {"HS512"},
		{"RS256"}, {"RS384"}, {"RS512"},
		{"ES256"}, {"ES384"}, {"ES512"},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			method, err := GetInternalSigningMethod(tt.alg)
			if err != nil {
				t.Fatalf("GetInternalSigningMethod(%q) failed: %v", tt.alg, err)
			}
			// Call Hash() to cover the method
			hash := method.Hash()
			if !hash.Available() {
				t.Errorf("Hash() for %s should be available", tt.alg)
			}
		})
	}
}

// =============================================================================
// NewManagerWithClock Tests
// =============================================================================

func TestNewManagerWithClock(t *testing.T) {
	store := NewMemoryStore(100, time.Minute, false)
	defer store.Close()

	// With custom clock
	fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	manager := NewManagerWithClock(store, func() time.Time { return fixedTime })
	if manager == nil {
		t.Fatal("NewManagerWithClock returned nil")
	}

	// Verify the clock is used by checking BlacklistToken uses correct time
	tokenID := "tok_clock_test"
	expiresAt := fixedTime.Add(-time.Hour) // Already expired relative to fixed clock
	err := manager.BlacklistToken(tokenID, expiresAt)
	if err != nil {
		t.Fatalf("BlacklistToken failed: %v", err)
	}

	// With nil clock (should use time.Now)
	store2 := NewMemoryStore(100, time.Minute, false)
	defer store2.Close()
	manager2 := NewManagerWithClock(store2, nil)
	if manager2 == nil {
		t.Fatal("NewManagerWithClock with nil clock returned nil")
	}
	manager2.Close()
}

// =============================================================================
// ParseTokenID Tests
// =============================================================================

func TestParseTokenID(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		wantID     string
		wantError  bool
	}{
		{
			name:   "valid token with jti",
			token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJ0b2tfMTIzNDU2In0.signature",
			wantID: "tok_123456",
		},
		{
			name:   "token without jti",
			token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidGVzdCJ9.signature",
			wantID: "",
		},
		{
			name:      "malformed token",
			token:     "malformed",
			wantError: true,
		},
		{
			name:      "empty token",
			token:     "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := ParseTokenID(tt.token)
			if tt.wantError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if id != tt.wantID {
				t.Errorf("ParseTokenID() = %q, want %q", id, tt.wantID)
			}
		})
	}
}

// =============================================================================
// Manager Close Edge Cases
// =============================================================================

func TestManagerCloseNilStore(t *testing.T) {
	manager := NewManager(nil)
	// Should not panic with nil store
	err := manager.Close()
	if err != nil {
		t.Errorf("Close with nil store should not error: %v", err)
	}
}

// =============================================================================
// Key Analysis Edge Case Tests
// =============================================================================

func TestKeyAnalysisEdgeCases(t *testing.T) {
	t.Run("ShortKey", func(t *testing.T) {
		if !hasLowEntropy([]byte("abc")) {
			t.Error("Short keys should be low entropy")
		}
	})

		t.Run("OnlyOneClass", func(t *testing.T) {
			// Only lowercase letters - should be weak (only 1 class)
			if !hasLowEntropy([]byte("abcdefghijklmnopqrstuvwx")) {
				t.Error("Single-class keys should be detected as low entropy")
			}
		})

	t.Run("SequentialWindow", func(t *testing.T) {
		// Key with sequential pattern in a window
		key := []byte("abcdefghRANDOMSTUFF")
		if !hasSequentialPattern(key, 8) {
			t.Error("Should detect sequential pattern in window")
		}
	})

	t.Run("NonSequentialWindow", func(t *testing.T) {
		key := []byte("a1b2c3d4e5f6g7h8")
		if hasSequentialPattern(key, 8) {
			t.Error("Should not detect sequential pattern in random key")
		}
	})

	t.Run("RepeatingPattern", func(t *testing.T) {
		if !hasRepeatingPattern([]byte("abcabcabc"), 3) {
			t.Error("Should detect 'abcabcabc' as repeating")
		}
	})

	t.Run("NonRepeatingPattern", func(t *testing.T) {
		if hasRepeatingPattern([]byte("aB3$fG7*k"), 3) {
			t.Error("Should not detect random string as repeating")
		}
	})

	t.Run("TooShortForRepeating", func(t *testing.T) {
		if hasRepeatingPattern([]byte("abc"), 3) {
			t.Error("Should not detect pattern when key is too short")
		}
	})

	t.Run("IsSequential", func(t *testing.T) {
		if !isSequential([]byte("abcdef")) {
			t.Error("abcdef should be sequential")
		}
		if !isSequential([]byte("fedcba")) {
			t.Error("fedcba should be sequential (descending)")
		}
		if isSequential([]byte("aB3$fG")) {
			t.Error("aB3$fG should not be sequential")
		}
		if isSequential([]byte("a")) {
			t.Error("Single byte should not be sequential")
		}
	})
}
