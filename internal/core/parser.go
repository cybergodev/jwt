package core

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/cybergodev/jwt/internal/signing"
)

var (
	errEmptyToken         = fmt.Errorf("empty token")
	errTokenTooLarge      = fmt.Errorf("token too large")
	errInvalidTokenFormat = fmt.Errorf("invalid token format")
)

func newTokenError(tokenType, message string, err error) error {
	if err != nil {
		return fmt.Errorf("token error (%s): %s: %w", tokenType, message, err)
	}
	return fmt.Errorf("token error (%s): %s", tokenType, message)
}

// NewTokenWithClaims creates a new token with the specified signing method and claims
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
	first := -1
	second := -1

	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			if first == -1 {
				first = i
			} else if second == -1 {
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

// ParseWithClaims parses a token string with claims
func ParseWithClaims(tokenString string, claims any, keyFunc func(*Core) (any, error)) (*Core, error) {
	if len(tokenString) == 0 {
		return nil, newTokenError("parse", "token cannot be empty", errEmptyToken)
	}

	const maxTokenLength = 8192
	if len(tokenString) > maxTokenLength {
		return nil, newTokenError("parse",
			fmt.Sprintf("token too large: maximum %d characters allowed", maxTokenLength),
			errTokenTooLarge)
	}

	if !isValidJWTFormat(tokenString) {
		return nil, newTokenError("parse", "invalid JWT format", errInvalidTokenFormat)
	}

	part1, part2, part3, ok := fastSplit3(tokenString, '.')
	if !ok {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts")
	}

	const maxPartLength = 4096
	if len(part1) > maxPartLength || len(part2) > maxPartLength || len(part3) > maxPartLength {
		return nil, fmt.Errorf("JWT part too large: maximum %d characters per part", maxPartLength)
	}

	parts := [3]string{part1, part2, part3}

	token := &Core{
		Raw: tokenString,
	}

	// Decode header
	if err := DecodeSegment(parts[0], &token.Header); err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	// Decode claims
	if err := DecodeSegment(parts[1], claims); err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	token.Claims = claims
	token.Signature = parts[2]

	alg, ok := token.Header["alg"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid alg header")
	}

	if alg == "" || alg == "none" {
		return nil, fmt.Errorf("insecure algorithm: %s", alg)
	}

	if isInsecureAlgorithm(alg) {
		return nil, fmt.Errorf("insecure algorithm detected: %s", alg)
	}

	method, err := signing.GetInternalSigningMethod(alg)
	if err != nil {
		return nil, fmt.Errorf("unsupported signing method: %s", alg)
	}

	token.Method = method

	key, err := keyFunc(token)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	signingString := parts[0] + "." + parts[1]

	if err := method.Verify(signingString, parts[2], key); err != nil {
		token.Valid = false
		return token, nil
	}

	token.Valid = true
	return token, nil
}

func ParseUnverified(tokenString string, claims any) (*Core, map[string]any, error) {
	if len(tokenString) == 0 {
		return nil, nil, fmt.Errorf("empty token")
	}

	const maxTokenLength = 8192
	if len(tokenString) > maxTokenLength {
		return nil, nil, fmt.Errorf("token too large: maximum %d characters allowed", maxTokenLength)
	}

	if !isValidJWTFormat(tokenString) {
		return nil, nil, fmt.Errorf("invalid JWT format")
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("invalid JWT format: expected 3 parts")
	}

	const maxPartLength = 4096
	if len(parts[0]) > maxPartLength || len(parts[1]) > maxPartLength || len(parts[2]) > maxPartLength {
		return nil, nil, fmt.Errorf("JWT part too large: maximum %d characters per part", maxPartLength)
	}

	// Decode header
	var header map[string]any
	if err := DecodeSegment(parts[0], &header); err != nil {
		return nil, nil, fmt.Errorf("failed to decode header: %w", err)
	}

	if alg, ok := header["alg"].(string); ok {
		if isInsecureAlgorithm(alg) {
			return nil, nil, fmt.Errorf("insecure algorithm detected")
		}
	}

	// Decode claims
	if err := DecodeSegment(parts[1], claims); err != nil {
		return nil, nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	token := &Core{
		Header:    header,
		Claims:    claims,
		Signature: parts[2],
		Raw:       tokenString,
		Valid:     false,
	}

	return token, header, nil
}

func isInsecureAlgorithm(alg string) bool {
	normalizedAlg := strings.ToUpper(strings.TrimSpace(alg))

	insecureAlgorithms := map[string]bool{
		"":      true, // Empty algorithm
		"NONE":  true, // No signature algorithm
		"HS1":   true, // Weak SHA-1 based HMAC
		"RS1":   true, // Weak SHA-1 based RSA
		"ES1":   true, // Weak SHA-1 based ECDSA
		"HS224": true, // Potentially weak SHA-224
		"RS224": true, // Potentially weak SHA-224
		"ES224": true, // Potentially weak SHA-224
		"NULL":  true, // Null algorithm
		"PLAIN": true, // Plain text (no security)
	}

	return insecureAlgorithms[normalizedAlg]
}

// SignedString creates a signed JWT token string
func (t *Core) SignedString(key any) (string, error) {
	return signing.SignedString(t.Header, t.Claims, t.Method, key)
}

// GenerateTokenIDFast creates a unique token identifier with cryptographically secure randomness
func GenerateTokenIDFast() string {
	bytes := make([]byte, TokenIDLength)

	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		if _, err := rand.Read(bytes); err == nil {
			break
		}
		if i == maxRetries-1 {
			panic("failed to generate secure random token ID after multiple attempts")
		}
		time.Sleep(time.Millisecond)
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

// isValidJWTFormat performs comprehensive JWT format validation to prevent malicious input
func isValidJWTFormat(token string) bool {
	if len(token) == 0 {
		return false
	}

	// Check for minimum reasonable length (header.payload.signature)
	if len(token) < 10 {
		return false
	}

	// Check for maximum reasonable length to prevent DoS
	if len(token) > 8192 {
		return false
	}

	dotCount := 0
	lastDotPos := -1

	for i, char := range token {
		if char == '.' {
			dotCount++
			// Check for consecutive dots
			if i == lastDotPos+1 {
				return false
			}
			lastDotPos = i
			continue
		}

		if !isBase64URLChar(char) {
			return false
		}
	}

	// Must have exactly 2 dots
	if dotCount != 2 {
		return false
	}

	// Check that token doesn't start or end with dot
	if token[0] == '.' || token[len(token)-1] == '.' {
		return false
	}

	// Validate that each part has reasonable length
	parts := strings.Split(token, ".")
	for i, part := range parts {
		if len(part) == 0 {
			return false
		}
		// Header and payload should have minimum length
		if i < 2 && len(part) < 4 {
			return false
		}
		// Signature should have reasonable length
		if i == 2 && len(part) < 8 {
			return false
		}
	}

	return true
}

// isBase64URLChar checks if a character is valid for base64url encoding
func isBase64URLChar(c rune) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
}
