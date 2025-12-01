package signing

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
)

// hmacSigningMethod implements HMAC-based JWT signing
type hmacSigningMethod struct {
	Name     string      // Algorithm name (e.g., "HS256")
	HashFunc crypto.Hash // Hash function to use
}

func (h *hmacSigningMethod) Verify(signingString string, signature string, key any) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("HMAC key must be []byte, got %T", key)
	}

	if !h.HashFunc.Available() {
		return fmt.Errorf("hash function %v not available", h.HashFunc)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	hasher := hmac.New(h.HashFunc.New, keyBytes)
	hasher.Write([]byte(signingString))
	expectedSigBytes := hasher.Sum(nil)

	if !hmac.Equal(sigBytes, expectedSigBytes) {
		return errors.New("signature verification failed")
	}

	return nil
}

func (h *hmacSigningMethod) Sign(signingString string, key any) (string, error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return "", fmt.Errorf("HMAC key must be []byte, got %T", key)
	}

	if !h.HashFunc.Available() {
		return "", fmt.Errorf("hash function %v not available", h.HashFunc)
	}

	hasher := hmac.New(h.HashFunc.New, keyBytes)
	hasher.Write([]byte(signingString))
	signature := hasher.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(signature), nil
}

func (h *hmacSigningMethod) Alg() string {
	return h.Name
}

func (h *hmacSigningMethod) Hash() crypto.Hash {
	return h.HashFunc
}

var (
	hmacHS256 = &hmacSigningMethod{"HS256", crypto.SHA256}
	hmacHS384 = &hmacSigningMethod{"HS384", crypto.SHA384}
	hmacHS512 = &hmacSigningMethod{"HS512", crypto.SHA512}
)

// GetHMACMethod returns the HMAC signing method for the given algorithm
func GetHMACMethod(alg string) Method {
	switch alg {
	case "HS256":
		return hmacHS256
	case "HS384":
		return hmacHS384
	case "HS512":
		return hmacHS512
	default:
		return nil
	}
}
