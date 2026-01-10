package internal

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

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

func GetInternalSigningMethod(alg string) (Method, error) {
	method := GetHMACMethod(alg)
	if method == nil {
		return nil, fmt.Errorf("unsupported signing method: %s", alg)
	}
	return method, nil
}
