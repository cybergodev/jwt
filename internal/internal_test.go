package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// HMAC Signing Method Tests
// =============================================================================

// methodHash extracts Hash() from a Method for tests. Hash is not part of the
// Method contract (no pipeline path reads it), so it is reached through a
// narrowing assertion.
func methodHash(m Method) crypto.Hash {
	return m.(interface{ Hash() crypto.Hash }).Hash()
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
			method, err := GetInternalSigningMethod(tt.alg)
			if err != nil {
				t.Fatalf("GetInternalSigningMethod(%q) failed: %v", tt.alg, err)
			}
			if method == nil {
				t.Fatalf("GetInternalSigningMethod(%q) returned nil", tt.alg)
			}

			if hash := methodHash(method); !hash.Available() {
				t.Skipf("Hash function %v not available on this platform", hash)
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
	if !strings.Contains(err.Error(), "invalid key type") {
		t.Errorf("Expected 'invalid key type' in error, got: %v", err)
	}

	// Test Verify with non-[]byte key
	err = method.Verify(signingString, "signature", "string-key")
	if err == nil {
		t.Error("Expected error for non-[]byte key in Verify, got nil")
	}
	if !strings.Contains(err.Error(), "invalid key type") {
		t.Errorf("Expected 'invalid key type' in error, got: %v", err)
	}

	// Test Verify with invalid base64 signature
	key := []byte("test-secret-key")
	err = method.Verify(signingString, "!!!invalid-base64!!!", key)
	if err == nil {
		t.Error("Expected error for invalid base64 signature, got nil")
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
		// RSA-PSS methods
		{"PS256", false},
		{"PS384", false},
		{"PS512", false},
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

// TestSignTokenRoundTrip signs via SignToken and parses the result back with
// ParseWithClaimsHMAC, verifying the payload survives the pooled-buffer
// encode/sign/decode round trip (not just the three-part shape).
func TestSignTokenRoundTrip(t *testing.T) {
	method, err := GetInternalSigningMethod("HS256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod failed: %v", err)
	}
	claims := map[string]any{
		"sub": "user123",
		"exp": 1234567890,
	}
	key := []byte("test-secret-key-with-sufficient-length-32bytes")

	tokenString, err := SignToken("HS256", claims, method, key)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}
	if tokenString == "" {
		t.Error("SignToken returned empty string")
	}
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		t.Errorf("Expected 3 parts, got %d", len(parts))
	}

	// Round trip: the signed token must parse, verify, and carry the payload.
	var decoded map[string]any
	core, err := ParseWithClaimsHMAC(tokenString, &decoded, key, "HS256")
	if err != nil {
		t.Fatalf("ParseWithClaimsHMAC failed: %v", err)
	}
	defer ReleaseCore(core)
	if !core.Valid {
		t.Error("Parsed token should be valid")
	}
	if decoded["sub"] != "user123" {
		t.Errorf("sub = %v, want user123", decoded["sub"])
	}
	if n, ok := decoded["exp"].(float64); !ok || int64(n) != 1234567890 {
		t.Errorf("exp = %v, want 1234567890", decoded["exp"])
	}
}

// TestSignTokenHMACRoundTrip covers the type-specialized HMAC entry point
// SignTokenHMAC, which the SignToken tests never reach: it must produce a
// token that parses and verifies, and must reject a non-HMAC method.
func TestSignTokenHMACRoundTrip(t *testing.T) {
	hm, err := GetInternalSigningMethod("HS256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod failed: %v", err)
	}
	claims := map[string]any{"sub": "hmac-user", "exp": 1234567890}
	key := []byte("test-secret-key-with-sufficient-length-32bytes")

	tokenString, err := SignTokenHMAC("HS256", claims, hm, key)
	if err != nil {
		t.Fatalf("SignTokenHMAC failed: %v", err)
	}

	var decoded map[string]any
	core, err := ParseWithClaimsHMAC(tokenString, &decoded, key, "HS256")
	if err != nil {
		t.Fatalf("ParseWithClaimsHMAC failed: %v", err)
	}
	defer ReleaseCore(core)
	if !core.Valid {
		t.Error("SignTokenHMAC output should verify")
	}
	if decoded["sub"] != "hmac-user" {
		t.Errorf("sub = %v, want hmac-user", decoded["sub"])
	}

	// The non-HMAC-method guard: passing an RSA method must error, not panic
	// or mis-sign.
	rsaMethod, err := GetInternalSigningMethod("RS256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod(RS256) failed: %v", err)
	}
	if _, err := SignTokenHMAC("HS256", claims, rsaMethod, key); err == nil {
		t.Error("SignTokenHMAC with non-HMAC method should fail")
	}
}

// brokenAppender implements JSONAppender with an always-failing AppendJSON,
// driving beginSigning's fast-path marshal-error branch.
type brokenAppender struct{}

func (brokenAppender) AppendJSON([]byte) ([]byte, error) {
	return nil, errors.New("appender failure")
}

// TestSignTokenErrors covers the error branches of beginSigning shared by
// SignToken and SignTokenHMAC: unknown algorithm, unencodable claims (slow
// Encode path), and a failing JSONAppender (fast path).
func TestSignTokenErrors(t *testing.T) {
	method, err := GetInternalSigningMethod("HS256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod failed: %v", err)
	}
	key := []byte("test-secret-key-with-sufficient-length-32bytes")

	tests := []struct {
		name   string
		alg    string
		claims any
	}{
		{"unknown algorithm", "XYZ999", map[string]any{"sub": "u"}},
		{"unencodable claims (channel)", "HS256", map[string]any{"bad": make(chan int)}},
		{"failing JSONAppender", "HS256", brokenAppender{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := SignToken(tt.alg, tt.claims, method, key); err == nil {
				t.Error("SignToken should fail")
			}
			if _, err := SignTokenHMAC(tt.alg, tt.claims, method, key); err == nil {
				t.Error("SignTokenHMAC should fail")
			}
		})
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
			tokenString: strings.Repeat("a", 140000),
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
			tokenString: strings.Repeat("a", 90000) + "." + "b" + "." + "c",
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

			_, err := ParseWithClaims(tt.tokenString, claims, keyFunc, "")
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
	key := []byte("test-secret-key-with-sufficient-length-32bytes")
	tokenString, err := SignToken("HS256", claims, method, key)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Parse with key function that returns error
	keyFunc := func(token *Core) (any, error) {
		return nil, &testError{msg: "test key function error"}
	}

	parsedClaims := make(map[string]any)
	_, err = ParseWithClaims(tokenString, &parsedClaims, keyFunc, "")
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
	key := []byte("test-secret-key-with-sufficient-length-32bytes")
	tokenString, err := SignToken("HS256", claims, method, key)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Parse with different key (signature verification should fail)
	wrongKey := []byte("wrong-secret-key-with-sufficient-length-32bytes")
	keyFunc := func(token *Core) (any, error) {
		return wrongKey, nil
	}

	parsedClaims := make(map[string]any)
	parsedToken, err := ParseWithClaims(tokenString, &parsedClaims, keyFunc, "")
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
			tokenString: strings.Repeat("a", 140000),
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
		{}, // empty key
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
	store := NewMemoryStore(100, time.Minute, false, nil)
	defer func() { _ = store.Close() }() // best-effort cleanup

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
	store := NewMemoryStore(100, time.Minute, false, nil)
	defer func() { _ = store.Close() }() // best-effort cleanup

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
	store := NewMemoryStore(100, time.Minute, false, nil)
	defer func() { _ = store.Close() }() // best-effort cleanup

	// Add expired tokens
	for i := 0; i < 5; i++ {
		tokenID := "expired-" + string(rune('0'+i))
		expiresAt := time.Now().Add(-time.Hour)
		_ = store.Add(tokenID, expiresAt) // test setup
	}

	// Add valid tokens
	for i := 0; i < 3; i++ {
		tokenID := "valid-" + string(rune('0'+i))
		expiresAt := time.Now().Add(time.Hour)
		_ = store.Add(tokenID, expiresAt) // test setup
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
	store := NewMemoryStore(maxSize, time.Minute, false, nil)
	defer func() { _ = store.Close() }() // best-effort cleanup

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
	ms := store // already *memoryStore since NewMemoryStore returns the concrete type
	ms.mu.RLock()
	size := len(ms.tokens)
	ms.mu.RUnlock()

	if size > maxSize {
		t.Errorf("Store size %d exceeds max size %d", size, maxSize)
	}
}

func TestMemoryStoreAutoCleanup(t *testing.T) {
	store := NewMemoryStore(100, 50*time.Millisecond, true, nil)
	defer func() { _ = store.Close() }() // best-effort cleanup

	// Add expired token
	tokenID := "auto-cleanup-token"
	expiresAt := time.Now().Add(-time.Hour)
	_ = store.Add(tokenID, expiresAt) // test setup

	// Wait for auto cleanup
	time.Sleep(100 * time.Millisecond)

	// Token should be cleaned up
	ms := store // already *memoryStore since NewMemoryStore returns the concrete type
	ms.mu.RLock()
	_, exists := ms.tokens[tokenID]
	ms.mu.RUnlock()

	if exists {
		t.Error("Expired token should have been auto-cleaned")
	}
}

func TestMemoryStoreClose(t *testing.T) {
	store := NewMemoryStore(100, time.Minute, true, nil)

	tokenID := "test-token"
	expiresAt := time.Now().Add(time.Hour)
	_ = store.Add(tokenID, expiresAt) // test setup

	// Close store
	err := store.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Operations after close should fail
	err = store.Add("new-token", time.Now().Add(time.Hour))
	if err != ErrStoreClosed {
		t.Errorf("Expected ErrStoreClosed, got %v", err)
	}

	_, err = store.Contains(tokenID)
	if err != ErrStoreClosed {
		t.Errorf("Expected ErrStoreClosed, got %v", err)
	}

	_, err = store.Cleanup()
	if err != ErrStoreClosed {
		t.Errorf("Expected ErrStoreClosed, got %v", err)
	}

	// Double close should be safe
	err = store.Close()
	if err != nil {
		t.Errorf("Double close should not error: %v", err)
	}
}

func TestMemoryStoreConcurrency(t *testing.T) {
	store := NewMemoryStore(1000, time.Minute, false, nil)
	defer func() { _ = store.Close() }() // best-effort cleanup

	done := make(chan bool)
	numGoroutines := 10
	tokensPerGoroutine := 100

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < tokensPerGoroutine; j++ {
				tokenID := string(rune('a'+id)) + "-" + string(rune('0'+j))
				expiresAt := time.Now().Add(time.Hour)
				_ = store.Add(tokenID, expiresAt) // stress test: error not actionable
				_, _ = store.Contains(tokenID)    // stress test: result ignored
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
	store := NewMemoryStore(1000, 5*time.Minute, false, nil)
	defer func() { _ = store.Close() }() // best-effort cleanup

	manager := NewManagerWithClock(store, nil)

	// Test with empty token ID
	err := manager.blacklistToken("", time.Now().Add(time.Hour))
	if err == nil {
		t.Error("Expected error for empty token ID")
	}
	if !strings.Contains(err.Error(), "token ID cannot be empty") {
		t.Errorf("Expected 'token ID cannot be empty' error, got %v", err)
	}

	// Test with valid token ID
	tokenID := "tok_valid123"
	expiresAt := time.Now().Add(time.Hour)
	err = manager.blacklistToken(tokenID, expiresAt)
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
	store := NewMemoryStore(1000, 5*time.Minute, false, nil)
	manager := NewManagerWithClock(store, nil)
	defer func() { _ = manager.Close() }() // best-effort cleanup

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

// TestManagerClose's trivial nil assertion was removed: close semantics are
// covered by TestMemoryStoreClose (post-close errors, double close) and
// TestManagerCloseNilStore below.

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

// TestRSASignAndVerify covers both RSA families (PKCS#1 v1.5 and PSS) in one
// table: the former TestPSSSignAndVerify duplicated this body verbatim.
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
		{"PS256"},
		{"PS384"},
		{"PS512"},
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
	if !strings.Contains(err.Error(), "invalid key type") {
		t.Errorf("Expected 'invalid key type' in error, got: %v", err)
	}

	// Test Verify with non-RSA key
	err = method.Verify(signingString, "signature", "string-key")
	if err == nil {
		t.Error("Expected error for non-RSA key in Verify, got nil")
	}
	if !strings.Contains(err.Error(), "invalid key type") {
		t.Errorf("Expected 'invalid key type' in error, got: %v", err)
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
	if !strings.Contains(err.Error(), "invalid key type") {
		t.Errorf("Expected 'invalid key type' in error, got: %v", err)
	}

	// Test Verify with non-ECDSA key
	err = method.Verify(signingString, "signature", "string-key")
	if err == nil {
		t.Error("Expected error for non-ECDSA key in Verify, got nil")
	}
	if !strings.Contains(err.Error(), "invalid key type") {
		t.Errorf("Expected 'invalid key type' in error, got: %v", err)
	}

	// Test Verify with invalid base64 signature
	err = method.Verify(signingString, "!!!invalid-base64!!!", &ecdsa.PublicKey{})
	if err == nil {
		t.Error("Expected error for invalid base64 signature, got nil")
	}

	// Degenerate keys must be rejected, not panic: an empty key struct has a
	// nil curve that would otherwise dereference nil inside crypto/ecdsa —
	// immediately when signing, and during Verify once a correctly-sized,
	// non-zero signature passes the length check ("_"×86 is raw-base64 for
	// 64×0xFF bytes).
	_, err = method.Sign(signingString, &ecdsa.PrivateKey{})
	if err == nil {
		t.Error("Expected error for empty ECDSA signing key, got nil")
	}
	err = method.Verify(signingString, strings.Repeat("_", 86), &ecdsa.PublicKey{})
	if err == nil {
		t.Error("Expected error for empty ECDSA public key, got nil")
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
	// Hash() is no longer part of the Method interface — no pipeline path
	// reads it — but every concrete implementation still exposes it.
	// Enumerate them directly to keep the coverage.
	methods := []interface {
		Alg() string
		Hash() crypto.Hash
	}{
		hmacHS256, hmacHS384, hmacHS512,
		rsaRS256, rsaRS384, rsaRS512,
		rsaPS256, rsaPS384, rsaPS512,
		ecdsaES256, ecdsaES384, ecdsaES512,
	}

	for _, m := range methods {
		if !m.Hash().Available() {
			t.Errorf("Hash() for %s should be available", m.Alg())
		}
	}
}

// TestNewManagerWithClock was removed: it only asserted non-nil returns, and
// the custom-clock path it gestured at is genuinely verified by
// TestBlacklistVerifiedTTLBounding (fixed clock drives the TTL bounds).

// =============================================================================
// Manager Close Edge Cases
// =============================================================================

func TestManagerCloseNilStore(t *testing.T) {
	manager := NewManagerWithClock(nil, nil)
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

// =============================================================================
// RSA-PSS Signing Method Tests
// =============================================================================

// TestPSSSignAndVerify was merged into TestRSASignAndVerify: identical
// body, same key shape, only the algorithm family differed.

func TestPSSSignTo(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	signingString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0"

	for _, alg := range []string{"PS256", "PS384", "PS512"} {
		t.Run(alg, func(t *testing.T) {
			method, err := GetInternalSigningMethod(alg)
			if err != nil {
				t.Fatalf("GetInternalSigningMethod(%q) failed: %v", alg, err)
			}

			dst := make([]byte, 512)
			n, err := method.SignTo(dst, signingString, privateKey)
			if err != nil {
				t.Fatalf("SignTo failed: %v", err)
			}
			if n == 0 {
				t.Error("SignTo wrote 0 bytes")
			}

			sig := string(dst[:n])
			err = method.Verify(signingString, sig, &privateKey.PublicKey)
			if err != nil {
				t.Errorf("Verify failed for SignTo output: %v", err)
			}

			smallBuf := make([]byte, 1)
			_, err = method.SignTo(smallBuf, signingString, privateKey)
			if err == nil {
				t.Error("Expected error for small buffer, got nil")
			}
		})
	}
}

func TestPSSInvalidKeyType(t *testing.T) {
	method, err := GetInternalSigningMethod("PS256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod failed: %v", err)
	}

	signingString := "test.data"

	_, err = method.Sign(signingString, "string-key")
	if err == nil {
		t.Error("Expected error for non-RSA key in Sign, got nil")
	}
	if !strings.Contains(err.Error(), "invalid key type") {
		t.Errorf("Expected 'invalid key type' in error, got: %v", err)
	}

	_, err = method.Sign(signingString, (*rsa.PrivateKey)(nil))
	if err == nil {
		t.Error("Expected error for nil key in Sign, got nil")
	}

	err = method.Verify(signingString, "signature", "string-key")
	if err == nil {
		t.Error("Expected error for non-RSA key in Verify, got nil")
	}
	if !strings.Contains(err.Error(), "invalid key type") {
		t.Errorf("Expected 'invalid key type' in error, got: %v", err)
	}

	err = method.Verify(signingString, "signature", (*rsa.PublicKey)(nil))
	if err == nil {
		t.Error("Expected error for nil public key in Verify, got nil")
	}

	err = method.Verify(signingString, "!!!invalid-base64!!!", &rsa.PublicKey{})
	if err == nil {
		t.Error("Expected error for invalid base64 signature, got nil")
	}
}

// TestPSSRegistryLookup was removed: a pure subset of
// TestGetInternalSigningMethod (registry lookup) and TestSigningMethodHash
// (Hash() availability), both of which already enumerate PS256/384/512.

// =============================================================================
// ECDSA SignTo Tests
// =============================================================================

func TestECDSASignTo(t *testing.T) {
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
				t.Fatalf("Failed to generate key: %v", err)
			}

			method, err := GetInternalSigningMethod(tt.alg)
			if err != nil {
				t.Fatalf("GetInternalSigningMethod(%q) failed: %v", tt.alg, err)
			}

			signingString := "test.data"

			dst := make([]byte, 256)
			n, err := method.SignTo(dst, signingString, privateKey)
			if err != nil {
				t.Fatalf("SignTo failed: %v", err)
			}
			if n == 0 {
				t.Error("SignTo wrote 0 bytes")
			}

			sig := string(dst[:n])
			err = method.Verify(signingString, sig, &privateKey.PublicKey)
			if err != nil {
				t.Errorf("Verify failed for SignTo output: %v", err)
			}

			smallBuf := make([]byte, 1)
			_, err = method.SignTo(smallBuf, signingString, privateKey)
			if err == nil {
				t.Error("Expected error for small buffer")
			}
		})
	}
}

// =============================================================================
// HMAC ClearCaches and DrainPool Tests
// =============================================================================

func TestClearHMACCaches(t *testing.T) {
	key := []byte("test-secret-key-with-sufficient-length-32bytes")
	signingString := "test.data"

	method, err := GetInternalSigningMethod("HS256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod failed: %v", err)
	}

	_, err = method.Sign(signingString, key)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	ClearHMACCaches()

	// Verify signing still works after clear
	_, err = method.Sign(signingString, key)
	if err != nil {
		t.Fatalf("Sign after clear failed: %v", err)
	}

	ClearHMACCaches()
	ClearHMACCaches()
}

// =============================================================================
// HMAC SignTo Tests
// =============================================================================

func TestHMACSignTo(t *testing.T) {
	key := []byte("test-secret-key-with-sufficient-length-32bytes")
	signingString := "test.data"

	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		t.Run(alg, func(t *testing.T) {
			method, err := GetInternalSigningMethod(alg)
			if err != nil {
				t.Fatalf("GetInternalSigningMethod(%q) failed: %v", alg, err)
			}

			dst := make([]byte, 128)
			n, err := method.SignTo(dst, signingString, key)
			if err != nil {
				t.Fatalf("SignTo failed: %v", err)
			}
			if n == 0 {
				t.Error("SignTo wrote 0 bytes")
			}

			sig := string(dst[:n])
			err = method.Verify(signingString, sig, key)
			if err != nil {
				t.Errorf("Verify failed for SignTo output: %v", err)
			}

			smallBuf := make([]byte, 1)
			_, err = method.SignTo(smallBuf, signingString, key)
			if err == nil {
				t.Error("Expected error for small buffer")
			}
		})
	}
}

// =============================================================================
// HMAC method Alg() Tests
// =============================================================================

// TestHMACSigningMethodAlg covers hmacSigningMethod.Alg(), which is otherwise
// 0% — the typed SignTo/Verify paths never route through the Method interface's
// Alg() for HMAC, unlike the RSA/ECDSA/PSS methods.
func TestHMACSigningMethodAlg(t *testing.T) {
	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		t.Run(alg, func(t *testing.T) {
			method, err := GetInternalSigningMethod(alg)
			if err != nil {
				t.Fatalf("GetInternalSigningMethod(%q) failed: %v", alg, err)
			}
			hm, ok := method.(*hmacSigningMethod)
			if !ok {
				t.Fatalf("expected *hmacSigningMethod, got %T", method)
			}
			if hm.Alg() != alg {
				t.Errorf("Alg() = %q, want %q", hm.Alg(), alg)
			}
		})
	}
}

// =============================================================================
// mapCapacity Tests
// =============================================================================

func TestMapCapacity(t *testing.T) {
	tests := []struct {
		name string
		size int
		want int
	}{
		{"negative returns floor", -1, 8},
		{"zero returns floor", 0, 8},
		{"below floor returns size", 5, 5},
		{"at floor returns size", 8, 8},
		{"at ceiling returns size", 64, 64},
		{"above ceiling capped", 100, 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mapCapacity(tt.size); got != tt.want {
				t.Errorf("mapCapacity(%d) = %d, want %d", tt.size, got, tt.want)
			}
		})
	}
}

// =============================================================================
// BlacklistVerified TTL Bounding Tests
// =============================================================================

// recordingStore is a minimal storeOps fake that captures the expiration
// passed to Add so the TTL-bounding logic in BlacklistVerified can be asserted.
type recordingStore struct {
	addedID  string
	addedExp time.Time
	addErr   error
}

func (r *recordingStore) Add(tokenID string, expiresAt time.Time) error {
	r.addedID = tokenID
	r.addedExp = expiresAt
	return r.addErr
}

func (r *recordingStore) Contains(string) (bool, error) { return false, nil }

func (r *recordingStore) Close() error { return nil }

// TestBlacklistVerifiedTTLBounding drives every branch of the TTL-bounding
// logic in manager.go:BlacklistVerified — zero exp, exp at/below default,
// exp between default and max, and exp beyond max.
func TestBlacklistVerifiedTTLBounding(t *testing.T) {
	base := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		expiresAt  time.Time
		wantExpOff time.Duration // expected stored expiry relative to base
	}{
		{"zero exp uses default TTL", time.Time{}, DefaultBlacklistTTL},
		{"exp below default uses default TTL", base.Add(time.Hour), DefaultBlacklistTTL},
		{"exp at default uses default TTL", base.Add(DefaultBlacklistTTL), DefaultBlacklistTTL},
		{"exp between default and max uses token exp", base.Add(10 * 24 * time.Hour), 10 * 24 * time.Hour},
		{"exp beyond max capped to max TTL", base.Add(100 * 24 * time.Hour), MaxBlacklistTTL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &recordingStore{}
			manager := NewManagerWithClock(store, func() time.Time { return base })

			if err := manager.BlacklistVerified("tok-123", tt.expiresAt); err != nil {
				t.Fatalf("BlacklistVerified failed: %v", err)
			}
			if store.addedID != "tok-123" {
				t.Errorf("stored token ID = %q, want %q", store.addedID, "tok-123")
			}
			want := base.Add(tt.wantExpOff)
			if !store.addedExp.Equal(want) {
				t.Errorf("stored expiry = %v, want %v", store.addedExp, want)
			}
		})
	}

	// Empty token ID is rejected before touching the store.
	store := &recordingStore{}
	manager := NewManagerWithClock(store, func() time.Time { return base })
	if err := manager.BlacklistVerified("", base.Add(time.Hour)); err == nil {
		t.Error("Expected error for empty token ID")
	}
}
