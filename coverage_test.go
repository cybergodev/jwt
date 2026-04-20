package jwt

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// ERROR TYPE TESTS (table-driven)
// ============================================================================

func TestErrorTypes(t *testing.T) {
	t.Run("TokenError", func(t *testing.T) {
		baseErr := errors.New("base error")
		tokenErr := &TokenError{Err: baseErr, TokenID: "tok_abc123", ExpiresAt: time.Now().Add(time.Hour)}

		if msg := tokenErr.Error(); !strings.Contains(msg, "tok_abc123") || !strings.Contains(msg, "token error") {
			t.Errorf("Error() = %q, want TokenID and 'token error'", msg)
		}
		if tokenErr.Unwrap() != baseErr {
			t.Errorf("Unwrap() = %v, want %v", tokenErr.Unwrap(), baseErr)
		}
		if !errors.Is(tokenErr, baseErr) {
			t.Error("errors.Is should match base error")
		}

		// Without TokenID
		noIDErr := &TokenError{Err: baseErr, TokenID: ""}
		if strings.Contains(noIDErr.Error(), "id=") {
			t.Error("Error() should not contain 'id=' when TokenID is empty")
		}
	})

	t.Run("SigningError", func(t *testing.T) {
		baseErr := errors.New("signing failed")
		signingErr := &SigningError{Algorithm: "RS256", Err: baseErr}

		if msg := signingErr.Error(); !strings.Contains(msg, "RS256") || !strings.Contains(msg, "signing error") {
			t.Errorf("Error() = %q, want algorithm and 'signing error'", msg)
		}
		if signingErr.Unwrap() != baseErr {
			t.Errorf("Unwrap() = %v, want %v", signingErr.Unwrap(), baseErr)
		}
	})

	t.Run("ValidationError", func(t *testing.T) {
		baseErr := errors.New("base error")
		valErr := &ValidationError{Field: "username", Message: "invalid format", Err: baseErr}

		want := "validation failed for field 'username': invalid format: base error"
		if valErr.Error() != want {
			t.Errorf("Error() = %q, want %q", valErr.Error(), want)
		}
		if valErr.Unwrap() != baseErr {
			t.Errorf("Unwrap() = %v, want %v", valErr.Unwrap(), baseErr)
		}

		valErr2 := &ValidationError{Field: "email", Message: "required"}
		if valErr2.Unwrap() != nil {
			t.Error("Unwrap() should return nil when Err is nil")
		}
	})

	t.Run("Constructors", func(t *testing.T) {
		baseErr := errors.New("test")
		tokenErr := NewTokenError(baseErr, "tok_123", time.Now().Add(time.Hour))
		if tokenErr.Err != baseErr || tokenErr.TokenID != "tok_123" {
			t.Errorf("NewTokenError fields wrong: %+v", tokenErr)
		}

		signingErr := NewSigningError("ES256", baseErr)
		if signingErr.Algorithm != "ES256" || signingErr.Err != baseErr {
			t.Errorf("NewSigningError fields wrong: %+v", signingErr)
		}
	})
}

// ============================================================================
// CLOCK PROVIDER TESTS
// ============================================================================

func TestClockProviders(t *testing.T) {
	t.Run("SystemClock", func(t *testing.T) {
		clock := SystemClock{}
		now := clock.Now()
		if now.IsZero() {
			t.Error("SystemClock.Now() should not return zero time")
		}
		if diff := time.Since(now); diff < 0 || diff > time.Second {
			t.Errorf("SystemClock.Now() unexpected time difference: %v", diff)
		}
	})

	t.Run("FixedClock", func(t *testing.T) {
		fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
		clock := FixedClock{T: fixedTime}

		if !clock.Now().Equal(fixedTime) {
			t.Errorf("FixedClock.Now() = %v, want %v", clock.Now(), fixedTime)
		}
		if !clock.Now().Equal(clock.Now()) {
			t.Error("FixedClock.Now() should return same time on multiple calls")
		}
	})
}

// ============================================================================
// RATE LIMITER TESTS (table-driven)
// ============================================================================

func TestRateLimiterBasic(t *testing.T) {
	t.Run("Allow", func(t *testing.T) {
		rl := NewRateLimiter(10, time.Second)
		defer rl.Close()

		for i := range 10 {
			if !rl.Allow("key") {
				t.Errorf("Allow should succeed at iteration %d", i)
			}
		}
		if rl.Allow("key") {
			t.Error("Should be rate limited after max")
		}
	})

	t.Run("AllowN", func(t *testing.T) {
		rl := NewRateLimiter(10, time.Second)
		defer rl.Close()

		tests := []struct {
			n    int
			want bool
		}{
			{0, true},
			{-1, false},
			{5, true},
			{5, true},
			{1, false},
			{100, false},
		}
		for _, tt := range tests {
			if got := rl.AllowN("key", tt.n); got != tt.want {
				t.Errorf("AllowN(%d) = %v, want %v", tt.n, got, tt.want)
			}
		}
	})

	t.Run("AllowN_EmptyKey", func(t *testing.T) {
		rl := NewRateLimiter(10, time.Second)
		defer rl.Close()

		if rl.AllowN("", 1) {
			t.Error("AllowN should reject empty key with n > 0")
		}
		// n=0 always returns true regardless of key
		if !rl.AllowN("", 0) {
			t.Error("AllowN with n=0 should return true")
		}
	})

	t.Run("Reset", func(t *testing.T) {
		rl := NewRateLimiter(10, time.Second)
		defer rl.Close()

		for range 10 {
			rl.Allow("key")
		}
		rl.Reset("key")
		for i := range 10 {
			if !rl.Allow("key") {
				t.Errorf("Should allow after reset, failed at %d", i)
			}
		}

		// Reset non-existent key should not panic
		rl.Reset("nonexistent")
		// Reset empty key should not panic
		rl.Reset("")
	})

	t.Run("TokenRefill", func(t *testing.T) {
		rl := NewRateLimiter(10, 100*time.Millisecond)
		defer rl.Close()

		for range 10 {
			rl.Allow("key")
		}
		if rl.Allow("key") {
			t.Error("Should be rate limited")
		}
		time.Sleep(150 * time.Millisecond)
		if !rl.Allow("key") {
			t.Error("Should have tokens after refill")
		}
	})

	t.Run("ClosedOperations", func(t *testing.T) {
		rl := NewRateLimiter(10, time.Second)
		rl.Close()

		if rl.Allow("test") {
			t.Error("Should not allow after close")
		}
		if rl.AllowN("test", 1) {
			t.Error("AllowN should not allow after close")
		}
		rl.Close() // double close should be safe
	})

	t.Run("Eviction", func(t *testing.T) {
		rl := NewRateLimiter(10, time.Second)
		defer rl.Close()

		rl.mu.Lock()
		rl.maxBuckets = 5
		rl.mu.Unlock()

		for i := range 6 {
			rl.Allow(fmt.Sprintf("key-%d", i))
			time.Sleep(time.Millisecond)
		}

		rl.mu.Lock()
		size := len(rl.buckets)
		rl.mu.Unlock()
		if size > 5 {
			t.Errorf("Expected max 5 buckets, got %d", size)
		}
	})

	t.Run("ZeroParameters", func(t *testing.T) {
		rl := NewRateLimiter(0, 0)
		rl.Close()
		rl = NewRateLimiter(100, 0)
		rl.Close()
	})
}

// ============================================================================
// PROCESSOR EDGE CASE TESTS
// ============================================================================

func TestProcessorIsClosed(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	if processor.IsClosed() {
		t.Error("Processor should not be closed initially")
	}
	processor.Close()
	if !processor.IsClosed() {
		t.Error("Processor should be closed after Close()")
	}
}

func TestProcessorOperationsAfterClose(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	processor.Close()

	claims := Claims{UserID: "user1", Username: "test"}

	tests := []struct {
		name string
		fn   func() error
	}{
		{"Create", func() error { _, e := processor.Create(&claims); return e }},
		{"Validate", func() error { _, _, e := processor.Validate("a.b.c"); return e }},
		{"CreateRefresh", func() error { _, e := processor.CreateRefresh(&claims); return e }},
		{"Refresh", func() error { _, e := processor.Refresh("a.b.c"); return e }},
		{"Revoke", func() error { return processor.Revoke("a.b.c") }},
		{"IsRevoked", func() error { _, e := processor.IsRevoked("a.b.c"); return e }},
		{"ParseUnverified", func() error { return processor.ParseUnverified("a.b.c", &Claims{}) }},
		{"ValidateInto", func() error { _, _, e := processor.ValidateInto("a.b.c", &claims); return e }},
		{"RefreshInto", func() error { _, e := processor.RefreshInto("a.b.c", &claims); return e }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); err != ErrProcessorClosed {
				t.Errorf("Expected ErrProcessorClosed, got %v", err)
			}
		})
	}

	// Double close
	if err := processor.Close(); err != ErrProcessorClosed {
		t.Errorf("Expected ErrProcessorClosed on double close, got %v", err)
	}
}

func TestRefreshTokenEdgeCases(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	tests := []struct {
		name      string
		token     string
		wantError error
	}{
		{"EmptyToken", "", ErrEmptyToken},
		{"MalformedToken", "malformed", nil},
		{"InvalidToken", "invalid.token.string", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := processor.Refresh(tt.token)
			if tt.wantError != nil {
				if err != tt.wantError {
					t.Errorf("Expected %v, got %v", tt.wantError, err)
				}
			} else if err == nil {
				t.Error("Expected error")
			}
		})
	}
}

// ============================================================================
// BLACKLIST EDGE CASE TESTS
// ============================================================================

func TestRevokeTokenEdgeCases(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Empty token
	if err := processor.Revoke(""); err != ErrEmptyToken {
		t.Errorf("Expected ErrEmptyToken, got %v", err)
	}

	// No blacklist configured
	if err := processor.Revoke("valid.token.string"); err == nil {
		t.Error("Expected error when no blacklist configured")
	}
}

func TestIsTokenRevokedEdgeCases(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	tests := []struct {
		name      string
		token     string
		wantError bool
	}{
		{"EmptyToken", "", true},
		{"MalformedToken", "malformed", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := processor.IsRevoked(tt.token)
			if tt.wantError && err == nil {
				t.Error("Expected error")
			}
		})
	}
}

func TestIsTokenRevokedInvalidToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.Blacklist = DefaultBlacklistConfig()
	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	revoked, err := processor.IsRevoked("invalid-token")
	if err == nil {
		t.Error("Expected error for invalid token")
	}
	if revoked {
		t.Error("Invalid token should not be considered revoked")
	}
}

// ============================================================================
// RATE LIMITING INTEGRATION TESTS
// ============================================================================

func TestProcessorRateLimiting(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.EnableRateLimit = true
	cfg.RateLimitRate = 5
	cfg.RateLimitWindow = time.Minute

	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{UserID: "ratelimited-user", Username: "test"}

	for range 5 {
		if _, err := processor.Create(&claims); err != nil {
			t.Fatalf("Should succeed within rate limit: %v", err)
		}
	}

	if _, err := processor.Create(&claims); err == nil {
		t.Error("Expected rate limit error")
	}
}

func TestProcessorWithCustomRateLimiter(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	defer rl.Close()

	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.RateLimiter = rl

	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{UserID: "custom-rl-user", Username: "test"}

	for range 5 {
		if _, err := processor.Create(&claims); err != nil {
			t.Fatalf("Should succeed within rate limit: %v", err)
		}
	}
	if _, err := processor.Create(&claims); err == nil {
		t.Error("Expected rate limit error with custom limiter")
	}
}

// ============================================================================
// REGISTERED CLAIMS VALIDATION TESTS
// ============================================================================

func TestRegisteredClaimsValidation(t *testing.T) {
	t.Run("IssuerMismatch", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.SecretKey = testSecretKey
		cfg.Issuer = "issuer-A"
		proc, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create processor: %v", err)
		}
		defer proc.Close()

		claims := Claims{UserID: "issuer-user", Username: "test"}
		token, err := proc.Create(&claims)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		cfg2 := DefaultConfig()
		cfg2.SecretKey = testSecretKey
		cfg2.Issuer = "issuer-B"
		proc2, err := New(cfg2)
		if err != nil {
			t.Fatalf("Failed to create processor: %v", err)
		}
		defer proc2.Close()

		_, valid, err := proc2.Validate(token)
		if valid || err == nil {
			t.Error("Should fail with mismatched issuer")
		}
	})

	t.Run("AudienceValidation", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.SecretKey = testSecretKey
		cfg.ExpectedAudience = "api-v1"
		proc, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create processor: %v", err)
		}
		defer proc.Close()

		// Token without audience should fail
		claims := Claims{UserID: "aud-user", Username: "test"}
		token, err := proc.Create(&claims)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}
		_, valid, err := proc.Validate(token)
		if valid || err == nil {
			t.Error("Should fail without matching audience")
		}

		// Token with matching audience should succeed
		claims2 := Claims{
			UserID:   "aud-user2",
			Username: "test",
			RegisteredClaims: RegisteredClaims{
				Audience: []string{"api-v1"},
			},
		}
		token2, err := proc.Create(&claims2)
		if err != nil {
			t.Fatalf("Failed to create token with audience: %v", err)
		}
		_, valid, err = proc.Validate(token2)
		if !valid || err != nil {
			t.Errorf("Should succeed with matching audience: %v", err)
		}
	})

	t.Run("NotBeforeFuture", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.SecretKey = testSecretKey
		cfg.Clock = FixedClock{T: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}
		proc, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create processor: %v", err)
		}
		defer proc.Close()

		claims := Claims{
			UserID:   "nbf-user",
			Username: "test",
			RegisteredClaims: RegisteredClaims{
				NotBefore: NewNumericDate(time.Date(2025, 1, 1, 13, 0, 0, 0, time.UTC)),
			},
		}
		token, err := createTokenWithCustomClaims(proc, &claims, time.Hour)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		_, valid, err := proc.Validate(token)
		if valid {
			t.Error("Token with future NotBefore should be invalid")
		}
		if !errors.Is(err, ErrTokenNotValidYet) {
			t.Errorf("Expected ErrTokenNotValidYet, got %v", err)
		}
	})
}

// ============================================================================
// GENERIC (CUSTOM CLAIMS) EDGE CASE TESTS
// ============================================================================

func TestRefreshTokenForEdgeCases(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := &TestCustomClaims{UserID: "rtf-user", Email: "rtf@example.com"}
	refreshToken, err := processor.CreateRefresh(claims)
	if err != nil {
		t.Fatalf("Failed to create refresh token: %v", err)
	}

	newClaims := &TestCustomClaims{}
	newToken, err := processor.RefreshInto(refreshToken, newClaims)
	if err != nil {
		t.Fatalf("RefreshInto failed: %v", err)
	}
	if newToken == "" {
		t.Error("Expected non-empty token")
	}

	validatedClaims := &TestCustomClaims{}
	_, valid, err := processor.ValidateInto(newToken, validatedClaims)
	if !valid || err != nil {
		t.Errorf("New access token should be valid: %v", err)
	}
}

func TestAlgorithmMismatch(t *testing.T) {
	cfg1 := DefaultConfig()
	cfg1.SecretKey = testSecretKey
	cfg1.SigningMethod = SigningMethodHS256
	proc1, err := New(cfg1)
	if err != nil {
		t.Fatalf("Failed to create HS256 processor: %v", err)
	}
	defer proc1.Close()

	token, err := proc1.Create(&Claims{UserID: "mismatch-user", Username: "test"})
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	cfg2 := DefaultConfig()
	cfg2.SecretKey = testSecretKey
	cfg2.SigningMethod = SigningMethodHS384
	proc2, err := New(cfg2)
	if err != nil {
		t.Fatalf("Failed to create HS384 processor: %v", err)
	}
	defer proc2.Close()

	_, valid, err := proc2.Validate(token)
	if valid || err == nil {
		t.Error("Should fail with algorithm mismatch")
	}
}

func TestValidateTokenIntoCustomClaimsInvalidSignature(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := &TestCustomClaims{UserID: "tamper-user", Email: "tamper@example.com"}
	token, err := processor.Create(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		parts[2] = "aW52YWxpZHNpZw"
		tamperedToken := strings.Join(parts, ".")
		validatedClaims := &TestCustomClaims{}
		_, valid, err := processor.ValidateInto(tamperedToken, validatedClaims)
		if valid || err == nil {
			t.Error("Tampered token should fail validation")
		}
	}
}

func TestValidateTokenForCustomClaims(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := &TestCustomClaims{UserID: "vtw-user", Email: "vtw@example.com"}
	token, err := processor.Create(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	validatedClaims := &TestCustomClaims{}
	result, valid, err := processor.ValidateInto(token, validatedClaims)
	if !valid || err != nil {
		t.Errorf("ValidateInto should work: %v", err)
	}
	if result.(*TestCustomClaims).UserID != "vtw-user" {
		t.Error("Claims mismatch")
	}
}

func TestParseUnverifiedEdgeCases(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{UserID: "parse-user", Username: "test"}
	token, err := processor.Create(&claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	parsedClaims := &Claims{}
	if err := processor.ParseUnverified(token, parsedClaims); err != nil {
		t.Fatalf("ParseUnverified failed: %v", err)
	}
	if parsedClaims.UserID != "parse-user" {
		t.Errorf("UserID = %s, want parse-user", parsedClaims.UserID)
	}

	tests := []struct {
		name      string
		token     string
		wantError bool
	}{
		{"EmptyToken", "", true},
		{"MalformedToken", "malformed", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := processor.ParseUnverified(tt.token, &Claims{})
			if tt.wantError && err == nil {
				t.Error("Expected error")
			}
		})
	}
}

// ============================================================================
// CLAIMS VALIDATION TESTS
// ============================================================================

func TestClaimsValidation(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	tests := []struct {
		name      string
		claims    Claims
		wantError bool
	}{
		{"EmptyBoth", Claims{}, true},
		{"OnlyUserID", Claims{UserID: "user1"}, false},
		{"OnlyUsername", Claims{Username: "user1"}, false},
		{"TooLongSessionID", Claims{UserID: "u", SessionID: strings.Repeat("a", 257)}, true},
		{"TooLongClientID", Claims{UserID: "u", ClientID: strings.Repeat("a", 257)}, true},
		{"TooLongRole", Claims{UserID: "u", Role: strings.Repeat("a", 257)}, true},
		{"DangerousRole", Claims{UserID: "u", Role: "<script>alert(1)</script>"}, true},
		{"DangerousSessionID", Claims{UserID: "u", SessionID: "javascript:alert(1)"}, true},
		{"ControlCharInClientID", Claims{UserID: "u", ClientID: "client\x00id"}, true},
		{"UnsupportedExtraType", Claims{UserID: "u", Extra: map[string]any{"key": 12345}}, true},
		{"ValidExtraStringAllowed", Claims{UserID: "u", Extra: map[string]any{"key": "value"}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := processor.Create(&tt.claims)
			if tt.wantError && err == nil {
				t.Error("Expected error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// ============================================================================
// VALIDATION REGISTERED CLAIMS STRINGS TESTS
// ============================================================================

func TestValidateRegisteredClaimsStrings(t *testing.T) {
	tests := []struct {
		name      string
		rc        RegisteredClaims
		wantError bool
	}{
		{"ValidDefaults", RegisteredClaims{}, false},
		{"ValidIssuer", RegisteredClaims{Issuer: "my-service"}, false},
		{"TooLongIssuer", RegisteredClaims{Issuer: strings.Repeat("a", 257)}, true},
		{"TooLongSubject", RegisteredClaims{Subject: strings.Repeat("a", 257)}, true},
		{"TooLongID", RegisteredClaims{ID: strings.Repeat("a", 257)}, true},
		{"TooManyAudience", RegisteredClaims{Audience: make([]string, 101)}, true},
		{"DangerousIssuer", RegisteredClaims{Issuer: "<script>alert(1)</script>"}, true},
		{"DangerousSubject", RegisteredClaims{Subject: "javascript:alert(1)"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRegisteredClaimsStrings(&tt.rc)
			if tt.wantError && err == nil {
				t.Error("Expected error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// ============================================================================
// RATE LIMIT KEY FOR CUSTOM CLAIMS
// ============================================================================

func TestRateLimitKeyer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.EnableRateLimit = true
	cfg.RateLimitRate = 3
	cfg.RateLimitWindow = time.Minute

	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// TestCustomClaims doesn't implement RateLimitKeyer, so rate limiting
	// should be skipped (no Subject set)
	claims := &TestCustomClaims{UserID: "rlk-user", Email: "rlk@example.com"}
	for range 10 {
		if _, err := processor.Create(claims); err != nil {
			t.Fatalf("Should not be rate limited without rate limit key: %v", err)
		}
	}
}

// ============================================================================
// WEAK KEY DETECTION (consolidated)
// ============================================================================

func TestWeakKeyDetectionConsolidated(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		isWeak bool
	}{
		// Weak patterns
		{"Empty", "", true},
		{"AllSameChar", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true},
		{"Sequential", "abcdefghijklmnopqrstuvwxyz123456", true},
		{"Repeating", "abababababababababababababababab", true},
		{"Keyboard", "qwertyuiopasdfghjklzxcvbnm123456", true},
		{"CommonWord", "passwordpasswordpasswordpassword", true},
		{"Numbers", "123123123123123123123123123123123", true},
		{"AllZeros", "000000000000000000000000000000000", true},

		// Strong keys
		{"StrongMixed", "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%", false},
		{"StrongYear", "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor, err := newTestProcessor(tt.key)
			if tt.isWeak {
				if err == nil {
					if processor != nil {
						processor.Close()
					}
					t.Errorf("Key %q should be rejected as weak", tt.name)
				}
			} else {
				if err != nil {
					t.Errorf("Key %q should be accepted: %v", tt.name, err)
				}
				if processor != nil {
					processor.Close()
				}
			}
		})
	}
}

// ============================================================================
// TOKEN MANAGER INTERFACE COMPLIANCE
// ============================================================================

func TestTokenManagerInterface(t *testing.T) {
	// Verify Processor implements TokenManager
	var _ TokenManager = (*Processor)(nil)
	var _ RateLimitProvider = (*RateLimiter)(nil)
	var _ ClockProvider = SystemClock{}
	var _ ClockProvider = FixedClock{}
	var _ CustomClaims = (*Claims)(nil)
	var _ CustomClaims = (*TestCustomClaims)(nil)
}

// ============================================================================
// CONCURRENT RATE LIMITER RESET
// ============================================================================

func TestRateLimiterConcurrentReset(t *testing.T) {
	rl := NewRateLimiter(100, time.Minute)
	defer rl.Close()

	var wg sync.WaitGroup
	var allowedCount int64

	wg.Add(10)
	for i := range 10 {
		go func(id int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", id)
			if rl.Allow(key) {
				_ = fmt.Sprintf("allowed %d", allowedCount)
			}
			rl.Reset(key)
		}(i)
	}
	wg.Wait()
}

// ============================================================================
// REFRESH CHAIN TEST
// ============================================================================

func TestRefreshChain(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{UserID: "chain-user", Username: "test", Role: "admin"}

	// Create initial refresh token
	refreshToken, err := processor.CreateRefresh(&claims)
	if err != nil {
		t.Fatalf("Failed to create initial refresh token: %v", err)
	}

	// Refresh to get access token
	accessToken, err := processor.Refresh(refreshToken)
	if err != nil {
		t.Fatalf("Failed to refresh: %v", err)
	}

	// Validate the access token
	parsed, valid, err := processor.Validate(accessToken)
	if err != nil || !valid {
		t.Fatalf("Access token should be valid: %v", err)
	}
	if parsed.UserID != claims.UserID {
		t.Errorf("UserID mismatch: got %s, want %s", parsed.UserID, claims.UserID)
	}
	if parsed.Role != claims.Role {
		t.Errorf("Role mismatch: got %s, want %s", parsed.Role, claims.Role)
	}
}
