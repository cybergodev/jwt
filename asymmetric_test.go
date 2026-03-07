package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestRSACreateAndValidateToken(t *testing.T) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	cfg := DefaultConfig()
	cfg.SigningKey = privateKey
	cfg.SigningMethod = SigningMethodRS256

	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{
		UserID:   "rsa-user",
		Username: "rsa-username",
		Role:     "admin",
	}

	// Create token
	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	if token == "" {
		t.Fatal("Token should not be empty")
	}

	// Validate token
	validatedClaims, valid, err := processor.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if !valid {
		t.Fatal("Token should be valid")
	}

	if validatedClaims.UserID != claims.UserID {
		t.Errorf("Expected UserID %s, got %s", claims.UserID, validatedClaims.UserID)
	}
}

func TestRSAWithDifferentKeySizes(t *testing.T) {
	keySizes := []int{2048, 3072}

	for _, keySize := range keySizes {
		t.Run(string(rune(keySize)), func(t *testing.T) {
			privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
			if err != nil {
				t.Fatalf("Failed to generate RSA key: %v", err)
			}

			cfg := DefaultConfig()
			cfg.SigningKey = privateKey
			cfg.SigningMethod = SigningMethodRS256

			processor, err := New(cfg)
			if err != nil {
				t.Fatalf("Failed to create processor: %v", err)
			}
			defer processor.Close()

			claims := Claims{
				UserID:   "test-user",
				Username: "test-username",
			}

			token, err := processor.CreateToken(claims)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			_, valid, err := processor.ValidateToken(token)
			if err != nil {
				t.Fatalf("Failed to validate token: %v", err)
			}

			if !valid {
				t.Fatal("Token should be valid")
			}
		})
	}
}

func TestRS384AndRS512(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	methods := []SigningMethod{SigningMethodRS256, SigningMethodRS384, SigningMethodRS512}

	for _, method := range methods {
		t.Run(string(method), func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.SigningKey = privateKey
			cfg.SigningMethod = method

			processor, err := New(cfg)
			if err != nil {
				t.Fatalf("Failed to create processor: %v", err)
			}
			defer processor.Close()

			claims := Claims{
				UserID:   "test-user",
				Username: "test-username",
			}

			token, err := processor.CreateToken(claims)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			_, valid, err := processor.ValidateToken(token)
			if err != nil {
				t.Fatalf("Failed to validate token: %v", err)
			}

			if !valid {
				t.Fatal("Token should be valid")
			}
		})
	}
}

func TestECDSACreateAndValidateToken(t *testing.T) {
	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	cfg := DefaultConfig()
	cfg.SigningKey = privateKey
	cfg.SigningMethod = SigningMethodES256

	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{
		UserID:   "ecdsa-user",
		Username: "ecdsa-username",
		Role:     "user",
	}

	// Create token
	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	if token == "" {
		t.Fatal("Token should not be empty")
	}

	// Validate token
	validatedClaims, valid, err := processor.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if !valid {
		t.Fatal("Token should be valid")
	}

	if validatedClaims.UserID != claims.UserID {
		t.Errorf("Expected UserID %s, got %s", claims.UserID, validatedClaims.UserID)
	}
}

func TestES384AndES512(t *testing.T) {
	methods := []struct {
		name   string
		method SigningMethod
		curve  elliptic.Curve
	}{
		{"ES256", SigningMethodES256, elliptic.P256()},
		{"ES384", SigningMethodES384, elliptic.P384()},
		{"ES512", SigningMethodES512, elliptic.P521()},
	}

	for _, tc := range methods {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key: %v", err)
			}

			cfg := DefaultConfig()
			cfg.SigningKey = privateKey
			cfg.SigningMethod = tc.method

			processor, err := New(cfg)
			if err != nil {
				t.Fatalf("Failed to create processor: %v", err)
			}
			defer processor.Close()

			claims := Claims{
				UserID:   "test-user",
				Username: "test-username",
			}

			token, err := processor.CreateToken(claims)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			_, valid, err := processor.ValidateToken(token)
			if err != nil {
				t.Fatalf("Failed to validate token: %v", err)
			}

			if !valid {
				t.Fatal("Token should be valid")
			}
		})
	}
}

func TestRSAWithPublicKeyVerification(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create processor with separate signing and verification keys
	cfg := DefaultConfig()
	cfg.SigningKey = privateKey
	cfg.SigningMethod = SigningMethodRS256

	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{
		UserID:   "test-user",
		Username: "test-username",
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	_, valid, err := processor.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if !valid {
		t.Fatal("Token should be valid")
	}
}

func TestAsymmetricInvalidKeyType(t *testing.T) {
	// Try to create processor with nil RSA key
	cfg := DefaultConfig()
	cfg.SigningKey = (*rsa.PrivateKey)(nil)
	cfg.SigningMethod = SigningMethodRS256

	_, err := New(cfg)
	if err == nil {
		t.Fatal("Expected error for nil RSA key")
	}

	// Try to create processor with nil ECDSA key
	cfg2 := DefaultConfig()
	cfg2.SigningKey = (*ecdsa.PrivateKey)(nil)
	cfg2.SigningMethod = SigningMethodES256

	_, err = New(cfg2)
	if err == nil {
		t.Fatal("Expected error for nil ECDSA key")
	}
}

func TestAsymmetricTokenRevocation(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	cfg := DefaultConfig()
	cfg.SigningKey = privateKey
	cfg.SigningMethod = SigningMethodRS256

	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{
		UserID:   "revoke-user",
		Username: "revoke-username",
	}

	token, err := processor.CreateToken(claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Validate should work
	_, valid, err := processor.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}
	if !valid {
		t.Fatal("Token should be valid before revocation")
	}

	// Revoke token
	err = processor.RevokeToken(token)
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	// Validate should fail now
	_, valid, err = processor.ValidateToken(token)
	if err != ErrTokenRevoked {
		t.Fatalf("Expected ErrTokenRevoked, got: %v", err)
	}
	if valid {
		t.Fatal("Token should not be valid after revocation")
	}
}

func TestAsymmetricClosedProcessor(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	cfg := DefaultConfig()
	cfg.SigningKey = privateKey
	cfg.SigningMethod = SigningMethodRS256

	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}

	// Close processor
	processor.Close()

	claims := Claims{
		UserID:   "closed-user",
		Username: "closed-username",
	}

	// All operations should fail
	_, err = processor.CreateToken(claims)
	if err != ErrProcessorClosed {
		t.Errorf("Expected ErrProcessorClosed, got: %v", err)
	}

	_, _, err = processor.ValidateToken("some-token")
	if err != ErrProcessorClosed {
		t.Errorf("Expected ErrProcessorClosed, got: %v", err)
	}
}
