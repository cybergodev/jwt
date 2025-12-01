package jwt

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// 🔒 COMPREHENSIVE SECURITY TESTS
// Focused security validation tests

func TestSecurityAlgorithmConfusion(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	maliciousTokens := []struct {
		name  string
		token string
	}{
		{"none algorithm", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoidGVzdCJ9."},
		{"empty algorithm", "eyJhbGciOiIiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyX2lkIjoidGVzdCJ9.invalid"},
		{"weak algorithm", "eyJhbGciOiJIUzEiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyX2lkIjoidGVzdCJ9.invalid"},
	}

	for _, tt := range maliciousTokens {
		t.Run(tt.name, func(t *testing.T) {
			_, valid, err := processor.ValidateToken(tt.token)
			if valid || err == nil {
				t.Errorf("Should reject %s token", tt.name)
			}
		})
	}
}

func TestSecurityWeakKeyDetection(t *testing.T) {
	weakKeys := []string{
		"password",
		"12345678901234567890123456789012",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"00000000000000000000000000000000",
		"secretsecretsecretsecretsecretsecret",
		"abcdefghijklmnopqrstuvwxyz123456",
		"qwertyuiopasdfghjklzxcvbnm123456",
		"passwordpasswordpasswordpassword",
	}

	for i, weakKey := range weakKeys {
		t.Run(fmt.Sprintf("WeakKey_%d", i), func(t *testing.T) {
			_, err := New(weakKey)
			if err == nil {
				t.Errorf("Should reject weak key: %s", weakKey)
			}
		})
	}
}

func TestSecurityInputValidation(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	maliciousClaims := []struct {
		name   string
		claims Claims
	}{
		{"XSS script tag", Claims{UserID: "<script>alert('xss')</script>", Username: "test"}},
		{"JavaScript injection", Claims{UserID: "test", Username: "javascript:alert(1)"}},
		{"Too long field", Claims{UserID: "test", Username: strings.Repeat("a", 1000)}},
		{"Null byte", Claims{UserID: "test\x00null", Username: "test"}},
		{"Path traversal", Claims{UserID: "../../../etc/passwd", Username: "test"}},
		{"Data URI", Claims{UserID: "data:text/html,<script>", Username: "test"}},
	}

	for _, tt := range maliciousClaims {
		t.Run(tt.name, func(t *testing.T) {
			_, err := processor.CreateToken(tt.claims)
			if err == nil {
				t.Errorf("Should reject malicious claims: %+v", tt.claims)
			}
		})
	}
}

func TestSecurityDoSProtection(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Test extremely long token
	longToken := strings.Repeat("a", 20000) + ".b.c"
	_, valid, err := processor.ValidateToken(longToken)
	if valid || err == nil {
		t.Error("Should reject extremely long tokens")
	}

	// Test too many permissions
	permissions := make([]string, 200)
	for i := range permissions {
		permissions[i] = fmt.Sprintf("perm%d", i)
	}
	claims := Claims{
		UserID:      "test",
		Username:    "test",
		Permissions: permissions,
	}
	if _, err := processor.CreateToken(claims); err == nil {
		t.Error("Should reject claims with too many permissions")
	}

	// Test too many extra fields
	extra := make(map[string]any)
	for i := 0; i < 100; i++ {
		extra[fmt.Sprintf("field%d", i)] = "value"
	}
	claims = Claims{
		UserID:   "test",
		Username: "test",
		Extra:    extra,
	}
	if _, err := processor.CreateToken(claims); err == nil {
		t.Error("Should reject claims with too many extra fields")
	}
}

func TestSecurityTimingAttackProtection(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{UserID: "test", Username: "test"}
	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Test with invalid signatures - timing should be consistent
	invalidTokens := []string{
		token[:len(token)-10] + "invalid123",
		token[:len(token)-10] + "wrong12345",
		token[:len(token)-10] + "fake123456",
	}

	var timings []time.Duration
	for _, invalidToken := range invalidTokens {
		start := time.Now()
		_, valid, _ := processor.ValidateToken(invalidToken)
		duration := time.Since(start)
		timings = append(timings, duration)

		if valid {
			t.Error("Invalid token should not be valid")
		}
	}

	// Check that timings are reasonably consistent (within 2x variance)
	if len(timings) >= 2 {
		minTime := timings[0]
		maxTime := timings[0]
		for _, timing := range timings[1:] {
			if timing < minTime {
				minTime = timing
			}
			if timing > maxTime {
				maxTime = timing
			}
		}

		if maxTime > minTime*2 {
			t.Logf("Warning: Large timing variance detected (min: %v, max: %v)", minTime, maxTime)
		}
	}
}

func TestSecurityInjectionPatterns(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Critical patterns that should be blocked
	criticalPatterns := []string{
		"<script>alert('xss')</script>",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"eval('alert(1)')",
		"../../../etc/passwd",
		"file:///etc/passwd",
		"vbscript:msgbox(1)",
	}

	for _, pattern := range criticalPatterns {
		claims := Claims{
			UserID:   pattern,
			Username: "test",
		}

		if _, err := processor.CreateToken(claims); err == nil {
			t.Errorf("Should reject critical injection pattern: %s", pattern)
		}
	}

	// Acceptable patterns (not security threats in JWT context)
	acceptablePatterns := []string{
		"user@example.com",
		"https://example.com/profile",
		"John O'Brien",
	}

	for _, pattern := range acceptablePatterns {
		claims := Claims{
			UserID:   "user123",
			Username: pattern,
		}

		if _, err := processor.CreateToken(claims); err != nil {
			t.Errorf("Should accept valid pattern: %s, got error: %v", pattern, err)
		}
	}
}

func TestSecurityConfigurationDefaults(t *testing.T) {
	config := DefaultConfig()

	// Should require secret key
	if config.SecretKey != "" {
		t.Error("Default config should not have a preset secret key")
	}

	// Should have reasonable TTL values
	if config.AccessTokenTTL > time.Hour {
		t.Error("Default access token TTL should be short for security")
	}

	if config.RefreshTokenTTL > 30*24*time.Hour {
		t.Error("Default refresh token TTL should be reasonable")
	}

	// Should use secure algorithm
	if config.SigningMethod != SigningMethodHS256 {
		t.Error("Default should use secure signing method")
	}
}

func TestSecurityMemoryHandling(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Create and validate multiple tokens to test memory handling
	for i := 0; i < 100; i++ {
		claims := Claims{
			UserID:   fmt.Sprintf("user%d", i),
			Username: fmt.Sprintf("test%d", i),
		}

		token, err := processor.CreateToken(claims)
		if err != nil {
			t.Fatalf("Failed to create token %d: %v", i, err)
		}

		_, valid, err := processor.ValidateToken(token)
		if err != nil || !valid {
			t.Fatalf("Failed to validate token %d: %v", i, err)
		}
	}

	// Test should complete without memory issues
	t.Log("Memory handling test completed successfully")
}

func TestSecurityKeyboardPatterns(t *testing.T) {
	keyboardPatternKeys := []string{
		"qwertyuiopasdfghjklzxcvbnm123456",
		"asdfghjklqwertyuiopzxcvbnm123456",
		"1234567890qwertyuiopasdfghjklzxc",
	}

	for _, weakKey := range keyboardPatternKeys {
		if _, err := New(weakKey); err == nil {
			t.Errorf("Should reject keyboard pattern key: %s", weakKey)
		}
	}
}

func TestSecurityLowEntropy(t *testing.T) {
	lowEntropyKeys := []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"abababababababababababababababab",
		"123123123123123123123123123123123",
		"000000000000000000000000000000000",
		"111111111111111111111111111111111",
	}

	for _, weakKey := range lowEntropyKeys {
		if _, err := New(weakKey); err == nil {
			t.Errorf("Should reject low entropy key: %s", weakKey)
		}
	}
}

func TestSecurityTokenValidation(t *testing.T) {
	processor, err := New(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Test malicious token patterns
	maliciousTokens := []string{
		"token\x00with\x00nulls",
		"token\x01with\x02control\x03chars",
		strings.Repeat("a", 20000),
		"<script>alert('xss')</script>.payload.sig",
	}

	for i, token := range maliciousTokens {
		_, valid, err := processor.ValidateToken(token)
		if valid || err == nil {
			maxLen := 50
			if len(token) < maxLen {
				maxLen = len(token)
			}
			t.Errorf("Test %d: Should reject malicious token: %s", i, token[:maxLen])
		}
	}
}
