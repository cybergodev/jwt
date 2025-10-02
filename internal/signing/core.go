package signing

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Method represents a signing method for JWT tokens
type Method interface {
	Alg() string
	Sign(signingString string, key any) (string, error)
	Verify(signingString string, signature string, key any) error
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

func validateAlgorithmSecurity(alg string) error {
	if alg == "" {
		return fmt.Errorf("algorithm cannot be empty")
	}

	normalizedAlg := strings.ToUpper(strings.TrimSpace(alg))

	secureAlgorithms := map[string]bool{
		"HS256": true, "HS384": true, "HS512": true,
	}

	if !secureAlgorithms[normalizedAlg] {
		return fmt.Errorf("algorithm %s is not secure", alg)
	}

	return nil
}

func GetInternalSigningMethod(alg string) (Method, error) {
	if err := validateAlgorithmSecurity(alg); err != nil {
		return nil, fmt.Errorf("algorithm security validation failed: %w", err)
	}

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
