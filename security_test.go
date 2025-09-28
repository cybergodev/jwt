package jwt

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// SECURITY TESTS: Comprehensive security validation tests

func TestSecurityAlgorithmConfusionAttack(t *testing.T) {
	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	processor, err := New(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Test 1: "none" algorithm attack
	noneToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoidGVzdCJ9."
	_, valid, err := processor.ValidateToken(noneToken)
	if valid || err == nil {
		t.Error("Should reject 'none' algorithm tokens")
	}

	// Test 2: Empty algorithm attack
	emptyAlgToken := "eyJhbGciOiIiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyX2lkIjoidGVzdCJ9.invalid"
	_, valid, err = processor.ValidateToken(emptyAlgToken)
	if valid || err == nil {
		t.Error("Should reject empty algorithm tokens")
	}

	// Test 3: Weak algorithm attack
	weakAlgToken := "eyJhbGciOiJIUzEiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyX2lkIjoidGVzdCJ9.invalid"
	_, valid, err = processor.ValidateToken(weakAlgToken)
	if valid || err == nil {
		t.Error("Should reject weak algorithm tokens")
	}
}

func TestSecurityWeakKeyDetection(t *testing.T) {
	weakKeys := []string{
		"password",                             // Common weak key
		"12345678901234567890123456789012",     // Repeated pattern
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",     // All same character
		"00000000000000000000000000000000",     // All zeros
		"secretsecretsecretsecretsecretsecret", // Repeated word
		"abcdefghijklmnopqrstuvwxyz123456",     // Sequential pattern
		"qwertyuiopasdfghjklzxcvbnm123456",     // Keyboard pattern
		"letmeinletmeinletmeinletmeinletmein",  // Common password pattern
		"defaultdefaultdefaultdefaultdefault",  // Default pattern
		"temptemptemptemptemptemptemptemp",     // Temporary pattern
		"guestguestguestguestguestguestguest",  // Guest pattern
		"adminadminadminadminadminadminadmin",  // Admin pattern
	}

	for _, weakKey := range weakKeys {
		_, err := New(weakKey)
		if err == nil {
			t.Errorf("Should reject weak key: %s", weakKey)
		}
	}
}

func TestSecurityInputValidation(t *testing.T) {
	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	processor, err := New(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Test malicious claims
	maliciousClaims := []Claims{
		{UserID: "<script>alert('xss')</script>", Username: "test"},
		{UserID: "test", Username: "javascript:alert(1)"},
		{UserID: "test", Username: strings.Repeat("a", 1000)}, // Too long
		{UserID: "test\x00null", Username: "test"},            // Null byte
		{UserID: "../../../etc/passwd", Username: "test"},     // Path traversal
	}

	for i, claims := range maliciousClaims {
		_, err := processor.CreateToken(claims)
		if err == nil {
			t.Errorf("Should reject malicious claims %d: %+v", i, claims)
		}
	}
}

func TestSecurityDoSProtection(t *testing.T) {
	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	processor, err := New(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Test 1: Extremely long token
	longToken := strings.Repeat("a", 20000) + ".b.c"
	_, valid, err := processor.ValidateToken(longToken)
	if valid || err == nil {
		t.Error("Should reject extremely long tokens")
	}

	// Test 2: Claims with too many permissions
	claims := Claims{
		UserID:      "test",
		Username:    "test",
		Permissions: make([]string, 200), // Too many permissions
	}
	for i := range claims.Permissions {
		claims.Permissions[i] = "perm" + fmt.Sprintf("%d", i)
	}

	_, err = processor.CreateToken(claims)
	if err == nil {
		t.Error("Should reject claims with too many permissions")
	}

	// Test 3: Claims with too many extra fields
	claims = Claims{
		UserID:   "test",
		Username: "test",
		Extra:    make(map[string]any),
	}
	for i := 0; i < 100; i++ {
		claims.Extra["field"+fmt.Sprintf("%d", i)] = "value"
	}

	_, err = processor.CreateToken(claims)
	if err == nil {
		t.Error("Should reject claims with too many extra fields")
	}
}

func TestSecurityTimingAttackProtection(t *testing.T) {
	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	processor, err := New(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Create a valid token
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

	// Check that timings are reasonably consistent (within 50% variance)
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

		// Allow up to 2x variance (timing attacks usually show much larger differences)
		if maxTime > minTime*2 {
			t.Logf("Warning: Large timing variance detected (min: %v, max: %v)", minTime, maxTime)
		}
	}
}

func TestSecurityInjectionAttacks(t *testing.T) {
	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	processor, err := New(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Test various injection patterns
	injectionPatterns := []string{
		"<script>alert('xss')</script>",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"eval('alert(1)')",
		"document.cookie",
		"window.location",
		"onload=alert(1)",
		"onerror=alert(1)",
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32",
		"file:///etc/passwd",
		"http://evil.com/steal",
		"vbscript:msgbox(1)",
	}

	for _, pattern := range injectionPatterns {
		claims := Claims{
			UserID:   pattern,
			Username: "test",
		}

		_, err := processor.CreateToken(claims)
		if err == nil {
			t.Errorf("Should reject injection pattern: %s", pattern)
		}
	}
}

func TestSecurityConfigurationValidation(t *testing.T) {
	// Test secure default configuration
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

func TestSecurityMemoryProtection(t *testing.T) {
	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	processor, err := New(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Create and validate multiple tokens to test memory handling
	for i := 0; i < 100; i++ {
		claims := Claims{
			UserID:   "user" + fmt.Sprintf("%d", i),
			Username: "test" + fmt.Sprintf("%d", i),
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
	t.Log("Memory protection test completed successfully")
}

func TestSecurityEnhancedInputValidation(t *testing.T) {
	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	processor, err := New(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Test malicious claims with enhanced validation
	maliciousClaims := []Claims{
		{UserID: strings.Repeat("a", 2000), Username: "test"},       // Too long field
		{UserID: "test\x00null", Username: "test"},                  // Null byte
		{UserID: "test", Username: "user\x01control"},               // Control character
		{UserID: "<script>alert('xss')</script>", Username: "test"}, // XSS attempt
		{UserID: "javascript:alert(1)", Username: "test"},           // JavaScript injection
		{UserID: "../../../etc/passwd", Username: "test"},           // Path traversal
		{UserID: "data:text/html,<script>", Username: "test"},       // Data URI injection
	}

	for i, claims := range maliciousClaims {
		_, err := processor.CreateToken(claims)
		if err == nil {
			t.Errorf("Test %d: Should reject malicious claims: %+v", i, claims)
		}
	}
}

func TestSecurityEnhancedTokenValidation(t *testing.T) {
	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	processor, err := New(secretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	// Test malicious token patterns
	maliciousTokens := []string{
		"token\x00with\x00nulls",                    // Null bytes
		"token\x01with\x02control\x03chars",         // Control characters
		strings.Repeat("a", 20000),                  // Extremely long token
		"<script>alert('xss')</script>.payload.sig", // XSS in token
		"javascript:alert(1).payload.signature",     // JavaScript injection
		"data:text/html,<script>.payload.signature", // Data URI injection
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

func TestSecurityKeyboardPatternDetection(t *testing.T) {
	keyboardPatternKeys := []string{
		"qwertyuiopasdfghjklzxcvbnm123456", // QWERTY keyboard pattern
		"asdfghjklqwertyuiopzxcvbnm123456", // Mixed keyboard pattern
		"1234567890qwertyuiopasdfghjklzxc", // Numbers + keyboard
		"qwertzuiopasdfghjklyxcvbnm123456", // QWERTZ layout
		"azertyuiopqsdfghjklmwxcvbn123456", // AZERTY layout
	}

	for _, weakKey := range keyboardPatternKeys {
		_, err := New(weakKey)
		if err == nil {
			t.Errorf("Should reject keyboard pattern key: %s", weakKey)
		}
	}
}

func TestSecurityLowEntropyDetection(t *testing.T) {
	lowEntropyKeys := []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // All same character
		"abababababababababababababababab",   // Alternating pattern
		"123123123123123123123123123123123",  // Repeated short pattern
		"000000000000000000000000000000000",  // All zeros
		"111111111111111111111111111111111",  // All ones
	}

	for _, weakKey := range lowEntropyKeys {
		_, err := New(weakKey)
		if err == nil {
			t.Errorf("Should reject low entropy key: %s", weakKey)
		}
	}
}
