package core

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/cybergodev/jwt/internal/signing"
)

var (
	errEmptyToken         = fmt.Errorf("empty token")
	errTokenTooLarge      = fmt.Errorf("token too large: maximum 8192 characters allowed")
	errInvalidTokenFormat = fmt.Errorf("invalid token format")
)

func NewTokenWithClaims(method signing.Method, claims any) *Core {
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
	sLen := len(s)
	first := -1
	second := -1

	for i := 0; i < sLen; i++ {
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
	tokenLen := len(tokenString)
	if tokenLen == 0 {
		return nil, errEmptyToken
	}

	const maxTokenLength = 8192
	if tokenLen > maxTokenLength {
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

	alg, ok := token.Header["alg"].(string)
	if !ok || alg == "" || isInsecureAlgorithm(alg) {
		return nil, fmt.Errorf("invalid or insecure algorithm")
	}

	method, err := signing.GetInternalSigningMethod(alg)
	if err != nil {
		return nil, fmt.Errorf("unsupported signing method: %s", alg)
	}
	token.Method = method

	if err := DecodeSegment(part2, claims); err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	key, err := keyFunc(token)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	signingString := part1 + "." + part2

	if err := method.Verify(signingString, part3, key); err != nil {
		token.Valid = false
		return token, nil
	}

	token.Valid = true
	return token, nil
}

func ParseUnverified(tokenString string, claims any) (*Core, map[string]any, error) {
	tokenLen := len(tokenString)
	if tokenLen == 0 {
		return nil, nil, errEmptyToken
	}

	const maxTokenLength = 8192
	if tokenLen > maxTokenLength {
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

	if alg, ok := header["alg"].(string); ok && isInsecureAlgorithm(alg) {
		return nil, nil, fmt.Errorf("insecure algorithm detected")
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
	upper := strings.ToUpper(strings.TrimSpace(alg))
	_, exists := insecureAlgorithms[upper]
	return exists
}

func (t *Core) SignedString(key any) (string, error) {
	return signing.SignedString(t.Header, t.Claims, t.Method, key)
}

func GenerateTokenIDFast() string {
	bytes := make([]byte, TokenIDLength)
	if _, err := rand.Read(bytes); err != nil {
		panic("crypto/rand is unavailable: " + err.Error())
	}

	const hexChars = "0123456789abcdef"
	result := make([]byte, 4+TokenIDLength*2)
	copy(result, "tok_")

	for i, b := range bytes {
		result[4+i*2] = hexChars[b>>4]
		result[4+i*2+1] = hexChars[b&0x0f]
	}

	return string(result)
}
