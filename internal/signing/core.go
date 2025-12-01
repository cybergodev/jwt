package signing

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Method represents a signing method for JWT tokens.
// Implementations must be thread-safe for concurrent use.
type Method interface {
	// Alg returns the algorithm name (e.g., "HS256")
	Alg() string

	// Sign creates a signature for the given signing string
	Sign(signingString string, key any) (string, error)

	// Verify verifies a signature against the signing string
	Verify(signingString string, signature string, key any) error

	// Hash returns the crypto.Hash used by this method
	Hash() crypto.Hash
}

func SignedString(header map[string]any, claims any, method Method, key any) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	headerEncodedLen := base64.RawURLEncoding.EncodedLen(len(headerJSON))
	claimsEncodedLen := base64.RawURLEncoding.EncodedLen(len(claimsJSON))

	signingStringBuf := make([]byte, headerEncodedLen+1+claimsEncodedLen)

	base64.RawURLEncoding.Encode(signingStringBuf[:headerEncodedLen], headerJSON)
	signingStringBuf[headerEncodedLen] = '.'
	base64.RawURLEncoding.Encode(signingStringBuf[headerEncodedLen+1:], claimsJSON)

	signingString := string(signingStringBuf)

	signature, err := method.Sign(signingString, key)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	tokenLen := len(signingString) + 1 + len(signature)
	tokenBuf := make([]byte, tokenLen)

	copy(tokenBuf, signingString)
	tokenBuf[len(signingString)] = '.'
	copy(tokenBuf[len(signingString)+1:], signature)

	return string(tokenBuf), nil
}

func GetInternalSigningMethod(alg string) (Method, error) {
	switch alg {
	case "HS256":
		return GetHMACMethod("HS256"), nil
	case "HS384":
		return GetHMACMethod("HS384"), nil
	case "HS512":
		return GetHMACMethod("HS512"), nil
	default:
		return nil, fmt.Errorf("unsupported signing method: %s", alg)
	}
}
