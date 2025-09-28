package jwt

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

// 🚀 COMPREHENSIVE BENCHMARK TESTS: Performance Analysis

func BenchmarkTokenCreation(b *testing.B) {
	// Create processor with disabled rate limiting for benchmarks
	config := Config{
		SecretKey:       testSecretKey,
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "test-service",
		SigningMethod:   SigningMethodHS256,
	}

	processor, err := NewWithBlacklist(testSecretKey, DefaultBlacklistConfig(), config)
	if err != nil {
		b.Fatalf("Failed to create processor: %v", err)
	}
	// Disable rate limiter for benchmarks
	processor.rateLimiter = nil
	defer processor.Close()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "admin",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := processor.CreateToken(claims)
		if err != nil {
			b.Fatalf("Failed to create token: %v", err)
		}
	}
}

func BenchmarkTokenValidation(b *testing.B) {
	processor, err := New(testSecretKey)
	if err != nil {
		b.Fatalf("Failed to create processor: %v", err)
	}
	// Disable rate limiter for benchmarks
	processor.rateLimiter = nil
	defer processor.Close()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "admin",
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		b.Fatalf("Failed to create token: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _, err := processor.ValidateToken(token)
		if err != nil {
			b.Fatalf("Failed to validate token: %v", err)
		}
	}
}

func BenchmarkTokenCreationAndValidation(b *testing.B) {
	processor, err := New(testSecretKey)
	if err != nil {
		b.Fatalf("Failed to create processor: %v", err)
	}
	// Disable rate limiter for benchmarks
	processor.rateLimiter = nil
	defer processor.Close()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "admin",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		token, err := processor.CreateToken(claims)
		if err != nil {
			b.Fatalf("Failed to create token: %v", err)
		}

		_, _, err = processor.ValidateToken(token)
		if err != nil {
			b.Fatalf("Failed to validate token: %v", err)
		}
	}
}

func BenchmarkConvenienceCreateToken(b *testing.B) {
	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "admin",
	}

	// Warm up cache and disable rate limiter
	_, err := CreateToken(testSecretKey, claims)
	if err != nil {
		b.Fatalf("Failed to warm up cache: %v", err)
	}

	// Get cached processor and disable rate limiter
	processor, err := getOrCreateProcessor(testSecretKey)
	if err != nil {
		b.Fatalf("Failed to get processor: %v", err)
	}
	processor.rateLimiter = nil

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := CreateToken(testSecretKey, claims)
		if err != nil {
			b.Fatalf("Failed to create token: %v", err)
		}
	}
}

func BenchmarkConvenienceValidateToken(b *testing.B) {
	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "admin",
	}

	// Create token and disable rate limiter
	token, err := CreateToken(testSecretKey, claims)
	if err != nil {
		b.Fatalf("Failed to create token: %v", err)
	}

	// Get cached processor and disable rate limiter
	processor, err := getOrCreateProcessor(testSecretKey)
	if err != nil {
		b.Fatalf("Failed to get processor: %v", err)
	}
	processor.rateLimiter = nil

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _, err := ValidateToken(testSecretKey, token)
		if err != nil {
			b.Fatalf("Failed to validate token: %v", err)
		}
	}
}

func BenchmarkBlacklistOperations(b *testing.B) {
	processor, err := NewWithBlacklist(testSecretKey, DefaultBlacklistConfig())
	if err != nil {
		b.Fatalf("Failed to create processor: %v", err)
	}
	// Disable rate limiter for benchmarks
	processor.rateLimiter = nil
	defer processor.Close()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "admin",
	}

	// Pre-create tokens for revocation benchmark
	tokens := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		token, err := processor.CreateToken(claims)
		if err != nil {
			b.Fatalf("Failed to create token %d: %v", i, err)
		}
		tokens[i] = token
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := processor.RevokeToken(tokens[i])
		if err != nil {
			b.Fatalf("Failed to revoke token: %v", err)
		}
	}
}

func BenchmarkBlacklistValidation(b *testing.B) {
	processor, err := NewWithBlacklist(testSecretKey, DefaultBlacklistConfig())
	if err != nil {
		b.Fatalf("Failed to create processor: %v", err)
	}
	// Disable rate limiter for benchmarks
	processor.rateLimiter = nil
	defer processor.Close()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "admin",
	}

	// Create and revoke some tokens
	const numRevokedTokens = 1000
	for i := 0; i < numRevokedTokens; i++ {
		token, err := processor.CreateToken(claims)
		if err != nil {
			b.Fatalf("Failed to create token %d: %v", i, err)
		}
		err = processor.RevokeToken(token)
		if err != nil {
			b.Fatalf("Failed to revoke token %d: %v", i, err)
		}
	}

	// Create a valid token for benchmarking
	validToken, err := processor.CreateToken(claims)
	if err != nil {
		b.Fatalf("Failed to create valid token: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _, err := processor.ValidateToken(validToken)
		if err != nil {
			b.Fatalf("Failed to validate token: %v", err)
		}
	}
}

func BenchmarkConcurrentTokenCreation(b *testing.B) {
	processor, err := New(testSecretKey)
	if err != nil {
		b.Fatalf("Failed to create processor: %v", err)
	}
	// Disable rate limiter for benchmarks
	processor.rateLimiter = nil
	defer processor.Close()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "admin",
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := processor.CreateToken(claims)
			if err != nil {
				b.Fatalf("Failed to create token: %v", err)
			}
		}
	})
}

func BenchmarkConcurrentTokenValidation(b *testing.B) {
	processor, err := New(testSecretKey)
	if err != nil {
		b.Fatalf("Failed to create processor: %v", err)
	}
	// Disable rate limiter for benchmarks
	processor.rateLimiter = nil
	defer processor.Close()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "admin",
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		b.Fatalf("Failed to create token: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := processor.ValidateToken(token)
			if err != nil {
				b.Fatalf("Failed to validate token: %v", err)
			}
		}
	})
}

func BenchmarkDifferentSigningMethods(b *testing.B) {
	signingMethods := []SigningMethod{
		SigningMethodHS256,
		SigningMethodHS384,
		SigningMethodHS512,
	}

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "admin",
	}

	for _, method := range signingMethods {
		b.Run(string(method), func(b *testing.B) {
			config := Config{
				SecretKey:       testSecretKey,
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 24 * time.Hour,
				Issuer:          "test-service",
				SigningMethod:   method,
			}

			processor, err := NewWithBlacklist(testSecretKey, DefaultBlacklistConfig(), config)
			if err != nil {
				b.Fatalf("Failed to create processor: %v", err)
			}
			// Disable rate limiter for benchmarks
			processor.rateLimiter = nil
			defer processor.Close()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				token, err := processor.CreateToken(claims)
				if err != nil {
					b.Fatalf("Failed to create token: %v", err)
				}

				_, _, err = processor.ValidateToken(token)
				if err != nil {
					b.Fatalf("Failed to validate token: %v", err)
				}
			}
		})
	}
}

func BenchmarkMemoryUsage(b *testing.B) {
	processor, err := New(testSecretKey)
	if err != nil {
		b.Fatalf("Failed to create processor: %v", err)
	}
	// Disable rate limiter for benchmarks
	processor.rateLimiter = nil
	defer processor.Close()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "admin",
	}

	// Force garbage collection before starting
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		token, err := processor.CreateToken(claims)
		if err != nil {
			b.Fatalf("Failed to create token: %v", err)
		}

		_, _, err = processor.ValidateToken(token)
		if err != nil {
			b.Fatalf("Failed to validate token: %v", err)
		}

		// Force GC every 1000 iterations to measure memory usage
		if i%1000 == 0 {
			runtime.GC()
		}
	}

	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	b.ReportMetric(float64(m2.Alloc-m1.Alloc)/float64(b.N), "bytes/op")
}

func BenchmarkLargeClaimsToken(b *testing.B) {
	processor, err := New(testSecretKey)
	if err != nil {
		b.Fatalf("Failed to create processor: %v", err)
	}
	// Disable rate limiter for benchmarks
	processor.rateLimiter = nil
	defer processor.Close()

	// Create claims with large data (reduced size for stability)
	permissions := make([]string, 20)
	for i := range permissions {
		permissions[i] = fmt.Sprintf("permission_%d", i)
	}

	extraData := make(map[string]any)
	for i := 0; i < 10; i++ {
		extraData[fmt.Sprintf("field_%d", i)] = fmt.Sprintf("value_%d", i)
	}

	claims := Claims{
		UserID:      "user123",
		Username:    "testuser",
		Role:        "admin",
		Permissions: permissions,
		Extra:       extraData,
	}

	b.ResetTimer()
	b.ReportAllocs()

	// Test token creation and validation once before benchmark
	testToken, err := processor.CreateToken(claims)
	if err != nil {
		b.Fatalf("Failed to create test token: %v", err)
	}
	_, valid, err := processor.ValidateToken(testToken)
	if err != nil {
		b.Fatalf("Failed to validate test token: %v", err)
	}
	if !valid {
		b.Fatalf("Test token is not valid")
	}

	for i := 0; i < b.N; i++ {
		token, err := processor.CreateToken(claims)
		if err != nil {
			b.Fatalf("Failed to create token: %v", err)
		}

		_, _, err = processor.ValidateToken(token)
		if err != nil {
			b.Fatalf("Failed to validate token: %v", err)
		}
	}
}

func BenchmarkProcessorCreation(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		processor, err := New(testSecretKey)
		if err != nil {
			b.Fatalf("Failed to create processor: %v", err)
		}
		processor.Close()
	}
}

func BenchmarkHighConcurrencyMixed(b *testing.B) {
	processor, err := NewWithBlacklist(testSecretKey, DefaultBlacklistConfig())
	if err != nil {
		b.Fatalf("Failed to create processor: %v", err)
	}
	// Disable rate limiter for benchmarks
	processor.rateLimiter = nil
	defer processor.Close()

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "admin",
	}

	// Pre-create some tokens
	const numPreTokens = 100
	preTokens := make([]string, numPreTokens)
	for i := 0; i < numPreTokens; i++ {
		token, err := processor.CreateToken(claims)
		if err != nil {
			b.Fatalf("Failed to create pre-token %d: %v", i, err)
		}
		preTokens[i] = token
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			switch i % 4 {
			case 0: // Create token
				_, err := processor.CreateToken(claims)
				if err != nil {
					b.Fatalf("Failed to create token: %v", err)
				}
			case 1: // Validate token
				tokenIdx := i % numPreTokens
				_, _, err := processor.ValidateToken(preTokens[tokenIdx])
				if err != nil {
					b.Fatalf("Failed to validate token: %v", err)
				}
			case 2: // Revoke token (occasionally)
				if i%10 == 0 {
					tokenIdx := i % numPreTokens
					processor.RevokeToken(preTokens[tokenIdx])
				}
			case 3: // Create and validate
				token, err := processor.CreateToken(claims)
				if err != nil {
					b.Fatalf("Failed to create token: %v", err)
				}
				_, _, err = processor.ValidateToken(token)
				if err != nil {
					b.Fatalf("Failed to validate token: %v", err)
				}
			}
			i++
		}
	})
}
