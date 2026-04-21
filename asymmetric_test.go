package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
)

func TestRSACreateAndValidateToken(t *testing.T) {
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

	claims := Claims{UserID: "rsa-user", Username: "rsa-username", Role: "admin"}

	token, err := processor.Create(&claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	validatedClaims, valid, err := processor.Validate(token)
	if err != nil || !valid {
		t.Fatalf("Failed to validate token: %v", err)
	}
	if validatedClaims.UserID != claims.UserID {
		t.Errorf("UserID: got %s, want %s", validatedClaims.UserID, claims.UserID)
	}
}

func TestRSAWithDifferentKeySizes(t *testing.T) {
	keySizes := []int{2048, 3072, 4096}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("bits_%d", keySize), func(t *testing.T) {
			if testing.Short() && keySize == 4096 {
				t.Skip("Skipping RSA-4096 in short mode")
			}

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

			claims := Claims{UserID: "test-user", Username: "test-username"}
			token, err := processor.Create(&claims)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			_, valid, err := processor.Validate(token)
			if err != nil || !valid {
				t.Fatalf("Token should be valid: %v", err)
			}
		})
	}
}

func TestAllRSAMethods(t *testing.T) {
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

			claims := Claims{UserID: "test-user", Username: "test-username"}
			token, err := processor.Create(&claims)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			_, valid, err := processor.Validate(token)
			if err != nil || !valid {
				t.Fatalf("Token should be valid: %v", err)
			}
		})
	}
}

func TestECDSACreateAndValidateToken(t *testing.T) {
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

	claims := Claims{UserID: "ecdsa-user", Username: "ecdsa-username", Role: "user"}

	token, err := processor.Create(&claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	validatedClaims, valid, err := processor.Validate(token)
	if err != nil || !valid {
		t.Fatalf("Failed to validate token: %v", err)
	}
	if validatedClaims.UserID != claims.UserID {
		t.Errorf("UserID: got %s, want %s", validatedClaims.UserID, claims.UserID)
	}
}

func TestAllECDSAMethods(t *testing.T) {
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

			claims := Claims{UserID: "test-user", Username: "test-username"}
			token, err := processor.Create(&claims)
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			_, valid, err := processor.Validate(token)
			if err != nil || !valid {
				t.Fatalf("Token should be valid: %v", err)
			}
		})
	}
}

func TestRSAWithPublicKeyVerification(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create processor with separate verification (public) key
	cfg := DefaultConfig()
	cfg.SigningKey = privateKey
	cfg.VerificationKey = &privateKey.PublicKey
	cfg.SigningMethod = SigningMethodRS256

	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{UserID: "test-user", Username: "test-username"}
	token, err := processor.Create(&claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	_, valid, err := processor.Validate(token)
	if err != nil || !valid {
		t.Fatalf("Token should validate with public key: %v", err)
	}
}

func TestAsymmetricInvalidKeyType(t *testing.T) {
	tests := []struct {
		name   string
		method SigningMethod
		key    any
	}{
		{"nil RSA key", SigningMethodRS256, (*rsa.PrivateKey)(nil)},
		{"nil ECDSA key", SigningMethodES256, (*ecdsa.PrivateKey)(nil)},
		{"string key for RSA", SigningMethodRS256, "string-key"},
		{"string key for ECDSA", SigningMethodES256, "string-key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.SigningKey = tt.key
			cfg.SigningMethod = tt.method
			_, err := New(cfg)
			if err == nil {
				t.Error("Expected error for wrong key type")
			}
		})
	}
}

func TestAsymmetricAlgorithmConfusion(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Create token with RSA
	rsaCfg := DefaultConfig()
	rsaCfg.SigningKey = rsaKey
	rsaCfg.SigningMethod = SigningMethodRS256
	rsaProc, err := New(rsaCfg)
	if err != nil {
		t.Fatalf("Failed to create RSA processor: %v", err)
	}
	defer rsaProc.Close()

	token, err := rsaProc.Create(&Claims{UserID: "confusion-user", Username: "test"})
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Try to validate with ECDSA processor (algorithm confusion attack)
	ecdsaCfg := DefaultConfig()
	ecdsaCfg.SigningKey = ecdsaKey
	ecdsaCfg.SigningMethod = SigningMethodES256
	ecdsaProc, err := New(ecdsaCfg)
	if err != nil {
		t.Fatalf("Failed to create ECDSA processor: %v", err)
	}
	defer ecdsaProc.Close()

	_, valid, err := ecdsaProc.Validate(token)
	if valid || err == nil {
		t.Error("Should reject RSA-signed token with ECDSA processor (algorithm confusion)")
	}
}

func TestECDSAWithPublicKeyVerification(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	cfg := DefaultConfig()
	cfg.SigningKey = privateKey
	cfg.VerificationKey = &privateKey.PublicKey
	cfg.SigningMethod = SigningMethodES256

	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	claims := Claims{UserID: "ecdsa-pub-user", Username: "test"}
	token, err := processor.Create(&claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	_, valid, err := processor.Validate(token)
	if err != nil || !valid {
		t.Fatalf("Token should validate with ECDSA public key: %v", err)
	}
}

func TestAsymmetricVerificationKeyValidation(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name    string
		method  SigningMethod
		signKey any
		verKey  any
	}{
		{"RSA wrong VerificationKey type", SigningMethodRS256, rsaKey, "string-key"},
		{"RSA nil typed VerificationKey", SigningMethodRS256, rsaKey, (*rsa.PublicKey)(nil)},
		{"ECDSA wrong VerificationKey type", SigningMethodES256, ecdsaKey, 12345},
		{"ECDSA nil typed VerificationKey", SigningMethodES256, ecdsaKey, (*ecdsa.PublicKey)(nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.SigningKey = tt.signKey
			cfg.VerificationKey = tt.verKey
			cfg.SigningMethod = tt.method
			_, err := New(cfg)
			if err == nil {
				t.Error("Expected error for invalid verification key")
			}
		})
	}
}

func TestECDSACurveMismatch(t *testing.T) {
	tests := []struct {
		name         string
		method       SigningMethod
		curve        elliptic.Curve
		wantErrMatch string
	}{
		{"ES256 with P-384 key", SigningMethodES256, elliptic.P384(), "P-256"},
		{"ES256 with P-521 key", SigningMethodES256, elliptic.P521(), "P-256"},
		{"ES384 with P-256 key", SigningMethodES384, elliptic.P256(), "P-384"},
		{"ES384 with P-521 key", SigningMethodES384, elliptic.P521(), "P-384"},
		{"ES512 with P-256 key", SigningMethodES512, elliptic.P256(), "P-521"},
		{"ES512 with P-384 key", SigningMethodES512, elliptic.P384(), "P-521"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key: %v", err)
			}

			cfg := DefaultConfig()
			cfg.SigningKey = privateKey
			cfg.SigningMethod = tt.method

			_, err = New(cfg)
			if err == nil {
				t.Fatal("Expected error for curve mismatch")
			}
			if err.Error() == "" {
				t.Error("Error message should not be empty")
			}
		})
	}
}
