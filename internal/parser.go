package internal

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	maxTokenLength = 8192
	TokenIDLength  = 16
)

var (
	errEmptyToken         = fmt.Errorf("empty token")
	errTokenTooLarge      = fmt.Errorf("token too large: maximum %d characters allowed", maxTokenLength)
	errInvalidTokenFormat = fmt.Errorf("invalid token format: expected 3 parts separated by dots")
	errEmptyHeader        = fmt.Errorf("empty header: JWT must have a valid header")
)

func NewTokenWithClaims(method Method, claims any) *Core {
	return &Core{
		Header: map[string]any{
			"typ": "JWT",
			"alg": method.Alg(),
		},
		Claims: claims,
		Method: method,
	}
}

func fastSplit3(s string, sep byte) (string, string, string, bool) {
	first := -1
	second := -1

	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			if first == -1 {
				first = i
			} else {
				second = i
				break
			}
		}
	}

	if first == -1 || second == -1 {
		return "", "", "", false
	}

	return s[:first], s[first+1 : second], s[second+1:], true
}

func ParseWithClaims(tokenString string, claims any, keyFunc func(*Core) (any, error)) (*Core, error) {
	if len(tokenString) == 0 {
		return nil, errEmptyToken
	}
	if len(tokenString) > maxTokenLength {
		return nil, errTokenTooLarge
	}

	part1, part2, part3, ok := fastSplit3(tokenString, '.')
	if !ok {
		return nil, errInvalidTokenFormat
	}

	token := &Core{
		Raw:       tokenString,
		Signature: part3,
		Claims:    claims,
	}

	if err := DecodeSegment(part1, &token.Header); err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	if len(token.Header) == 0 {
		return nil, errEmptyHeader
	}

	alg, ok := token.Header["alg"].(string)
	if !ok || alg == "" {
		return nil, fmt.Errorf("missing or invalid algorithm in header")
	}
	if isInsecureAlgorithm(alg) {
		return nil, fmt.Errorf("insecure algorithm not allowed: %s", alg)
	}

	method, err := GetInternalSigningMethod(alg)
	if err != nil {
		return nil, err
	}
	token.Method = method

	if err := DecodeSegment(part2, claims); err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	key, err := keyFunc(token)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	signingStringLen := len(part1) + 1 + len(part2)
	signingStringBuf := make([]byte, signingStringLen)
	copy(signingStringBuf, part1)
	signingStringBuf[len(part1)] = '.'
	copy(signingStringBuf[len(part1)+1:], part2)
	signingString := string(signingStringBuf)

	if err := method.Verify(signingString, part3, key); err != nil {
		token.Valid = false
		return token, nil
	}

	token.Valid = true
	return token, nil
}

func ParseUnverified(tokenString string, claims any) (*Core, map[string]any, error) {
	if len(tokenString) == 0 {
		return nil, nil, errEmptyToken
	}
	if len(tokenString) > maxTokenLength {
		return nil, nil, errTokenTooLarge
	}

	part1, part2, part3, ok := fastSplit3(tokenString, '.')
	if !ok {
		return nil, nil, errInvalidTokenFormat
	}

	var header map[string]any
	if err := DecodeSegment(part1, &header); err != nil {
		return nil, nil, fmt.Errorf("failed to decode header: %w", err)
	}

	if len(header) == 0 {
		return nil, nil, errEmptyHeader
	}

	if alg, ok := header["alg"].(string); ok && isInsecureAlgorithm(alg) {
		return nil, nil, fmt.Errorf("insecure algorithm detected: %s", alg)
	}

	if err := DecodeSegment(part2, claims); err != nil {
		return nil, nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	token := &Core{
		Header:    header,
		Claims:    claims,
		Signature: part3,
		Raw:       tokenString,
		Valid:     false,
	}

	return token, header, nil
}

var insecureAlgorithms = map[string]struct{}{
	"":      {},
	"NONE":  {},
	"NULL":  {},
	"PLAIN": {},
	"HS1":   {},
	"RS1":   {},
	"ES1":   {},
	"HS224": {},
	"RS224": {},
	"ES224": {},
}

func isInsecureAlgorithm(alg string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(alg))
	_, exists := insecureAlgorithms[normalized]
	return exists
}

func (t *Core) SignedString(key any) (string, error) {
	return SignedString(t.Header, t.Claims, t.Method, key)
}

func GenerateTokenIDFast() (string, error) {
	randomBytes := make([]byte, TokenIDLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}

	result := make([]byte, 4+TokenIDLength*2)
	copy(result, "tok_")
	hex.Encode(result[4:], randomBytes)

	return string(result), nil
}
