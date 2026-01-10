package internal

import (
	"crypto"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// HMAC Signing Method Tests
// =============================================================================

func TestGetHMACMethod(t *testing.T) {
	tests := []struct {
		alg      string
		wantNil  bool
		wantHash crypto.Hash
	}{
		{"HS256", false, crypto.SHA256},
		{"HS384", false, crypto.SHA384},
		{"HS512", false, crypto.SHA512},
		{"HS128", true, 0},
		{"invalid", true, 0},
		{"", true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			method := GetHMACMethod(tt.alg)
			if tt.wantNil {
				if method != nil {
					t.Errorf("Expected nil for %q, got %v", tt.alg, method)
				}
			} else {
				if method == nil {
					t.Fatalf("Expected method for %q, got nil", tt.alg)
				}
				if method.Alg() != tt.alg {
					t.Errorf("Expected alg %q, got %q", tt.alg, method.Alg())
				}
				if method.Hash() != tt.wantHash {
					t.Errorf("Expected hash %v, got %v", tt.wantHash, method.Hash())
				}
			}
		})
	}
}

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
			method := GetHMACMethod(tt.alg)
			if method == nil {
				t.Fatalf("GetHMACMethod(%q) returned nil", tt.alg)
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
	method := GetHMACMethod("HS256")
	signingString := "test.data"

	// Test Sign with non-[]byte key
	_, err := method.Sign(signingString, "string-key")
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
	method := GetHMACMethod("HS256")
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
		{"HS256", false},
		{"HS384", false},
		{"HS512", false},
		{"", true},
		{"none", true},
		{"RS256", true},
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
	method := GetHMACMethod("HS256")
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
	method := GetHMACMethod("HS256")
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

func TestGenerateTokenIDFast(t *testing.T) {
	id1, err := GenerateTokenIDFast()
	if err != nil {
		t.Fatalf("GenerateTokenIDFast failed: %v", err)
	}

	if len(id1) != 4+TokenIDLength*2 {
		t.Errorf("Expected length %d, got %d", 4+TokenIDLength*2, len(id1))
	}

	if !strings.HasPrefix(id1, "tok_") {
		t.Errorf("Expected prefix 'tok_', got %q", id1[:4])
	}

	id2, err := GenerateTokenIDFast()
	if err != nil {
		t.Fatalf("GenerateTokenIDFast failed: %v", err)
	}
	if id1 == id2 {
		t.Error("Generated IDs should be unique")
	}

	// Test uniqueness with 100 IDs
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := GenerateTokenIDFast()
		if err != nil {
			t.Fatalf("GenerateTokenIDFast failed: %v", err)
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
	method := GetHMACMethod("HS256")
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
	method := GetHMACMethod("HS256")
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
		[]byte("abcdefghijklmnopqrstuvwxyz123456"), // sequential
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

