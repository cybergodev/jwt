package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cybergodev/jwt/internal"
)

// ============================================================================
// ERROR TYPE TESTS (table-driven)
// ============================================================================

func TestErrorTypes(t *testing.T) {
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
	_ = processor.Close() // cleanup
	if !processor.IsClosed() {
		t.Error("Processor should be closed after Close()")
	}
}

func TestProcessorOperationsAfterClose(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	_ = processor.Close() // cleanup

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
}

func TestRefreshTokenEdgeCases(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

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

func TestRevokeAndIsRevokedEdgeCases(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	t.Run("RevokeEmptyToken", func(t *testing.T) {
		if err := processor.Revoke(""); err != ErrEmptyToken {
			t.Errorf("Expected ErrEmptyToken, got %v", err)
		}
	})

	t.Run("RevokeNoBlacklist", func(t *testing.T) {
		if err := processor.Revoke("valid.token.string"); err == nil {
			t.Error("Expected error when no blacklist configured")
		}
	})

	t.Run("IsRevokedEmptyToken", func(t *testing.T) {
		_, err := processor.IsRevoked("")
		if err == nil {
			t.Error("Expected error")
		}
	})

	t.Run("IsRevokedMalformedToken", func(t *testing.T) {
		_, err := processor.IsRevoked("malformed")
		if err == nil {
			t.Error("Expected error")
		}
	})
}

func TestIsTokenRevokedInvalidToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.Blacklist = DefaultBlacklistConfig()
	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

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
	tests := []struct {
		name  string
		setup func(t *testing.T) (*Processor, func())
	}{
		{
			name: "built-in limiter",
			setup: func(t *testing.T) (*Processor, func()) {
				cfg := DefaultConfig()
				cfg.SecretKey = testSecretKey
				cfg.EnableRateLimit = true
				cfg.RateLimitRate = 5
				cfg.RateLimitWindow = time.Minute
				p, err := New(cfg)
				if err != nil {
					t.Fatalf("Failed to create processor: %v", err)
				}
				return p, func() { _ = p.Close() }
			},
		},
		{
			name: "custom limiter",
			setup: func(t *testing.T) (*Processor, func()) {
				rl := NewRateLimiter(5, time.Minute)
				cfg := DefaultConfig()
				cfg.SecretKey = testSecretKey
				cfg.RateLimiter = rl
				p, err := New(cfg)
				if err != nil {
					t.Fatalf("Failed to create processor: %v", err)
				}
				return p, func() { _ = p.Close(); rl.Close() }
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor, cleanup := tt.setup(t)
			defer cleanup()

			// Rate-limit key falls back to UserID when Subject is empty.
			claims := Claims{UserID: "rl-user", Username: "test"}

			for range 5 {
				if _, err := processor.Create(&claims); err != nil {
					t.Fatalf("Should succeed within rate limit: %v", err)
				}
			}
			if _, err := processor.Create(&claims); err == nil {
				t.Error("Expected rate limit error after exhausting allowance")
			}
		})
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
		defer func() { _ = proc.Close() }() // best-effort cleanup

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
		defer func() { _ = proc2.Close() }() // best-effort cleanup

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
		defer func() { _ = proc.Close() }() // best-effort cleanup

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
		defer func() { _ = proc.Close() }() // best-effort cleanup

		claims := Claims{
			UserID:   "nbf-user",
			Username: "test",
			RegisteredClaims: RegisteredClaims{
				NotBefore: NewNumericDate(time.Date(2025, 1, 1, 13, 0, 0, 0, time.UTC)),
			},
		}
		token, err := createTokenWithCustomClaims(proc, &claims, time.Hour, TokenTypeAccess)
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
	defer func() { _ = processor.Close() }() // best-effort cleanup

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

func TestValidateTokenIntoCustomClaimsInvalidSignature(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

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
	defer func() { _ = processor.Close() }() // best-effort cleanup

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
	defer func() { _ = processor.Close() }() // best-effort cleanup

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
// PROCESSOR INTERNAL BRANCH TESTS (white-box)
// ============================================================================

// TestRevokeWithoutJTICoversVerifyAndExtractID covers the missing-jti branch
// of verifyAndExtractID shared by Revoke and IsRevoked: a token without a jti
// cannot be revoked, because the blacklist is keyed by that ID. The token is
// signed directly (signClaims does not auto-fill jti, unlike Create) with a
// matching issuer so the earlier issuer/audience checks pass.
func TestRevokeWithoutJTICoversVerifyAndExtractID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.Blacklist = DefaultBlacklistConfig()
	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := &Claims{UserID: "nojti-user"}
	claims.Issuer = processor.issuer
	token, err := processor.signClaims(claims)
	if err != nil {
		t.Fatalf("signClaims failed: %v", err)
	}

	if err := processor.Revoke(token); !errors.Is(err, ErrTokenMissingID) {
		t.Errorf("Revoke: errors.Is(err, ErrTokenMissingID) = false, err = %v", err)
	}
	if _, err := processor.IsRevoked(token); !errors.Is(err, ErrTokenMissingID) {
		t.Errorf("IsRevoked: errors.Is(err, ErrTokenMissingID) = false, err = %v", err)
	}
}

// TestKeyFuncHeaderAlgFallback covers keyFunc's defensive Header lookup: when
// the cached fast-path Alg is empty, the header map is consulted, and a
// non-string or mismatched alg must yield ErrAlgorithmMismatch. keyFunc runs
// only on the asymmetric parse path, so an RSA processor is used.
func TestKeyFuncHeaderAlgFallback(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	cfg := DefaultConfig()
	cfg.SigningKey = rsaKey
	cfg.SigningMethod = SigningMethodRS256
	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	tests := []struct {
		name      string
		headerAlg any
		wantErr   error
	}{
		{"matching alg from header", "RS256", nil},
		{"mismatched alg from header", "RS512", ErrAlgorithmMismatch},
		{"non-string alg in header", 42, ErrAlgorithmMismatch},
		{"missing alg in header", nil, ErrAlgorithmMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core := &internal.Core{Header: map[string]any{"alg": tt.headerAlg}}
			key, err := processor.keyFunc(core)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("keyFunc err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("keyFunc err = %v", err)
			}
			if key != processor.verificationKey {
				t.Fatalf("keyFunc key = %T, want the configured verification key", key)
			}
		})
	}
}

// TestSignClaimsDefensiveBranches covers signClaims' constructor-guaranteed
// invariants (non-nil method impl, non-nil key) as returned errors rather
// than panics, reachable only by direct field mutation.
func TestSignClaimsDefensiveBranches(t *testing.T) {
	t.Run("nil signing method", func(t *testing.T) {
		processor, err := newTestProcessor(testSecretKey)
		if err != nil {
			t.Fatalf("Failed to create processor: %v", err)
		}
		defer func() { _ = processor.Close() }() // best-effort cleanup

		method := processor.signingMethodImpl
		processor.signingMethodImpl = nil
		defer func() { processor.signingMethodImpl = method }()

		if _, err := processor.signClaims(&Claims{UserID: "u"}); err == nil {
			t.Error("signClaims with nil method impl should fail")
		}
	})

	t.Run("nil HMAC secret", func(t *testing.T) {
		processor, err := newTestProcessor(testSecretKey)
		if err != nil {
			t.Fatalf("Failed to create processor: %v", err)
		}
		defer func() { _ = processor.Close() }() // best-effort cleanup

		key := processor.secretKey
		processor.secretKey = nil
		defer func() { processor.secretKey = key }()

		if _, err := processor.signClaims(&Claims{UserID: "u"}); err == nil {
			t.Error("signClaims with nil HMAC secret should fail")
		}
	})

	t.Run("nil asymmetric key", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}
		cfg := DefaultConfig()
		cfg.SigningKey = rsaKey
		cfg.SigningMethod = SigningMethodRS256
		processor, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create processor: %v", err)
		}
		defer func() { _ = processor.Close() }() // best-effort cleanup

		key := processor.asymmetricKey
		processor.asymmetricKey = nil
		defer func() { processor.asymmetricKey = key }()

		if _, err := processor.signClaims(&Claims{UserID: "u"}); err == nil {
			t.Error("signClaims with nil asymmetric key should fail")
		}
	})
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
	defer func() { _ = processor.Close() }() // best-effort cleanup

	// TestCustomClaims doesn't implement RateLimitKeyer, so rate limiting
	// should be skipped (no Subject set)
	claims := &TestCustomClaims{UserID: "rlk-user", Email: "rlk@example.com"}
	for range 10 {
		if _, err := processor.Create(claims); err != nil {
			t.Fatalf("Should not be rate limited without rate limit key: %v", err)
		}
	}
}

// TestValidateClaimsFailureWrapsSentinel guards the contract documented in the
// README: errors.Is(err, jwt.ErrInvalidClaims) must hold for claims-validation
// failures on the Validate path, not just Create. Create blocks empty claims, so
// we sign an otherwise-impossible empty-claims token via the unexported signer to
// drive validateTokenFully's claims.Validate() branch.
func TestValidateClaimsFailureWrapsSentinel(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	// Empty user fields but a matching issuer, so validateRegistered does not
	// short-circuit and we reach claims.Validate(). Bypasses Create validation
	// but carries a valid signature so only claims.Validate() fails.
	claims := &Claims{}
	claims.Issuer = processor.issuer
	token, err := processor.signClaims(claims)
	if err != nil {
		t.Fatalf("signClaims failed: %v", err)
	}

	_, _, err = processor.Validate(token)
	if err == nil {
		t.Fatal("Expected error for token with empty claims")
	}
	if !errors.Is(err, ErrInvalidClaims) {
		t.Errorf("Validate claims failure must wrap ErrInvalidClaims; got %v", err)
	}
}

// descriptiveClaims is a custom claims type whose Validate() returns a
// descriptive error (NOT the ErrInvalidClaims sentinel), matching the pattern
// documented on Claims.Validate. It is used to verify the generic paths
// (ValidateInto/RefreshInto) wrap claims failures in ErrInvalidClaims so
// errors.Is(err, ErrInvalidClaims) holds symmetrically with Validate/Refresh.
// Returning a non-sentinel error is essential: a type that returns the sentinel
// itself would satisfy errors.Is regardless of whether the wrap is present.
type descriptiveClaims struct {
	UserID string `json:"user_id,omitempty"`
	RegisteredClaims
}

func (c *descriptiveClaims) GetRegisteredClaims() *RegisteredClaims {
	return &c.RegisteredClaims
}

// Validate returns a descriptive error when UserID is empty.
func (c *descriptiveClaims) Validate() error {
	if c.UserID == "" {
		return errors.New("user_id is required")
	}
	return nil
}

// TestValidateIntoClaimsFailureWrapsSentinel is the ValidateInto counterpart to
// TestValidateClaimsFailureWrapsSentinel. It verifies that a claims-validation
// failure on the generic ValidateInto path wraps ErrInvalidClaims, restoring
// errors.Is(err, ErrInvalidClaims) symmetry with the built-in Validate path.
func TestValidateIntoClaimsFailureWrapsSentinel(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	// Empty UserID so descriptiveClaims.Validate() returns a descriptive error;
	// matching issuer so validateRegistered does not short-circuit. Signed
	// directly (bypassing Create's validation) with a valid signature so only
	// claims.Validate() fails inside validateCustomTokenFully.
	claims := &descriptiveClaims{}
	claims.Issuer = processor.issuer
	token, err := processor.signClaims(claims)
	if err != nil {
		t.Fatalf("signClaims failed: %v", err)
	}

	_, _, err = processor.ValidateInto(token, &descriptiveClaims{})
	if err == nil {
		t.Fatal("Expected error for token with empty claims")
	}
	if !errors.Is(err, ErrInvalidClaims) {
		t.Errorf("ValidateInto claims failure must wrap ErrInvalidClaims; got %v", err)
	}
}

// TestRefreshIntoClaimsFailureWrapsSentinel mirrors the above for the
// RefreshInto path: a refresh-token claims-validation failure must wrap
// ErrInvalidClaims, symmetric with the built-in Refresh path.
func TestRefreshIntoClaimsFailureWrapsSentinel(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	// Marked as refresh so the TokenTypeAccess guard does not fire; the empty
	// UserID still makes claims.Validate() fail first inside
	// validateCustomTokenFully.
	claims := &descriptiveClaims{}
	claims.Issuer = processor.issuer
	claims.TokenType = TokenTypeRefresh
	token, err := processor.signClaims(claims)
	if err != nil {
		t.Fatalf("signClaims failed: %v", err)
	}

	_, err = processor.RefreshInto(token, &descriptiveClaims{})
	if err == nil {
		t.Fatal("Expected error for refresh token with empty claims")
	}
	if !errors.Is(err, ErrInvalidClaims) {
		t.Errorf("RefreshInto claims failure must wrap ErrInvalidClaims; got %v", err)
	}
}

// TestRequireExpiration covers the Config.RequireExpiration toggle: a token
// lacking exp is rejected when the flag is on, accepted when off, and exp-bearing
// tokens validate normally either way. Tokens are crafted via signClaims (which
// does not auto-fill exp, unlike Create) so the no-exp case is reachable.
func TestRequireExpiration(t *testing.T) {
	newProcessor := func(requireExp bool) *Processor {
		cfg := DefaultConfig()
		cfg.SecretKey = testSecretKey
		cfg.RequireExpiration = requireExp
		p, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create processor: %v", err)
		}
		return p
	}

	// A signed token whose payload carries no exp (NumericDate{} marshals to null).
	// Issuer is set to match the processor so the issuer check does not short-circuit
	// the test before validateRegistered's exp gate is evaluated.
	noExpToken := func(p *Processor) string {
		tok, err := p.signClaims(&Claims{UserID: "no-exp-user", RegisteredClaims: RegisteredClaims{Issuer: p.issuer}})
		if err != nil {
			t.Fatalf("signClaims failed: %v", err)
		}
		return tok
	}

	t.Run("rejects no-exp token when enabled", func(t *testing.T) {
		p := newProcessor(true)
		defer func() { _ = p.Close() }()
		_, valid, err := p.Validate(noExpToken(p))
		if valid {
			t.Error("token without exp must not be valid when RequireExpiration is on")
		}
		if !errors.Is(err, ErrExpirationRequired) {
			t.Errorf("expected ErrExpirationRequired, got %v", err)
		}
	})

	t.Run("accepts no-exp token when disabled", func(t *testing.T) {
		p := newProcessor(false)
		defer func() { _ = p.Close() }()
		_, valid, err := p.Validate(noExpToken(p))
		if err != nil || !valid {
			t.Errorf("token without exp should validate when RequireExpiration is off; valid=%v err=%v", valid, err)
		}
	})

	t.Run("exp-bearing token validates when enabled", func(t *testing.T) {
		p := newProcessor(true)
		defer func() { _ = p.Close() }()
		token, err := p.Create(&Claims{UserID: "with-exp-user"})
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		if _, valid, err := p.Validate(token); !valid || err != nil {
			t.Errorf("exp-bearing token should validate; valid=%v err=%v", valid, err)
		}
	})
}
