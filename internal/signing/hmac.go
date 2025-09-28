package signing

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/cybergodev/jwt/internal/security"
)

type hmacSigningMethod struct {
	Name     string
	HashFunc crypto.Hash
}

func (h *hmacSigningMethod) Verify(signingString string, signature string, key any) error {
	var secureKey *security.SecureBytes
	var keyBytes []byte

	switch k := key.(type) {
	case []byte:
		secureKey = security.NewSecureBytesFromSlice(k)
		keyBytes = secureKey.Bytes()
	case string:
		secureKey = security.NewSecureBytesFromSlice([]byte(k))
		keyBytes = secureKey.Bytes()
		// Note: Cannot safely zero string due to immutability - use []byte for sensitive data
	default:
		return fmt.Errorf("HMAC key must be []byte or string, got %T", key)
	}

	defer secureKey.Destroy()

	//  Enforce minimum key length for cryptographic security
	if len(keyBytes) < 32 {
		return fmt.Errorf("HMAC key too short: minimum 32 bytes required for security, got %d", len(keyBytes))
	}

	//  Check for weak keys (all zeros, repeated patterns)
	if security.IsWeakKey(keyBytes) {
		return fmt.Errorf("weak HMAC key detected: key must have sufficient entropy")
	}

	if !h.HashFunc.Available() {
		return fmt.Errorf("hash function %v not available", h.HashFunc)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	defer security.ZeroBytes(sigBytes)

	hasher := hmac.New(h.HashFunc.New, keyBytes)
	hasher.Write([]byte(signingString))
	expectedSigBytes := hasher.Sum(nil)
	defer security.ZeroBytes(expectedSigBytes)

	//  Constant-time comparison to prevent timing attacks
	if !security.SecureCompare(sigBytes, expectedSigBytes) {
		// Add secure random delay to prevent timing analysis
		security.SecureRandomDelay()
		return errors.New("signature verification failed")
	}

	return nil
}

func (h *hmacSigningMethod) Sign(signingString string, key any) (string, error) {
	var secureKey *security.SecureBytes
	var keyBytes []byte

	switch k := key.(type) {
	case []byte:
		secureKey = security.NewSecureBytesFromSlice(k)
		keyBytes = secureKey.Bytes()
	case string:
		secureKey = security.NewSecureBytesFromSlice([]byte(k))
		keyBytes = secureKey.Bytes()
		// Note: Cannot safely zero string due to immutability
	default:
		return "", fmt.Errorf("HMAC key must be []byte or string, got %T", key)
	}

	defer secureKey.Destroy()

	//  Enforce minimum key length for cryptographic security
	if len(keyBytes) < 32 {
		return "", fmt.Errorf("HMAC key too short: minimum 32 bytes required for security, got %d", len(keyBytes))
	}

	//  Check for weak keys (all zeros, repeated patterns)
	if security.IsWeakKey(keyBytes) {
		return "", fmt.Errorf("weak HMAC key detected: key must have sufficient entropy")
	}

	if !h.HashFunc.Available() {
		return "", fmt.Errorf("hash function %v not available", h.HashFunc)
	}

	hasher := hmac.New(h.HashFunc.New, keyBytes)
	hasher.Write([]byte(signingString))
	signature := hasher.Sum(nil)
	defer security.ZeroBytes(signature)

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
