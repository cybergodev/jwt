package internal

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

const (
	maxTokenLength = 8192
)

var (
	errEmptyToken         = fmt.Errorf("empty token")
	errTokenTooLarge      = fmt.Errorf("token too large: maximum %d characters allowed", maxTokenLength)
	errInvalidTokenFormat = fmt.Errorf("invalid token format: expected 3 parts separated by dots")
	errEmptyHeader        = fmt.Errorf("empty header: JWT must have a valid header")
	errEmptySignature     = fmt.Errorf("empty signature: JWT must have a valid signature")

	// ErrAlgorithmMismatch indicates that the token's algorithm does not match
	// the expected signing method.
	ErrAlgorithmMismatch = errors.New("token algorithm does not match configured signing method")
)

// parseBufPool pools byte slices for parsing operations.
var parseBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 512)
		return &buf
	},
}

func getParseBuf() *[]byte {
	return parseBufPool.Get().(*[]byte)
}

func putParseBuf(buf *[]byte) {
	if cap(*buf) <= 2048 {
		*buf = (*buf)[:0]
		parseBufPool.Put(buf)
	}
}

// corePool pools Core structs to reduce allocations during token parsing.
var corePool = sync.Pool{
	New: func() any {
		return &Core{
			Header: make(map[string]any, 2),
		}
	},
}

// ReleaseCore returns a Core struct to the pool after clearing its fields.
func ReleaseCore(c *Core) {
	clear(c.Header)
	c.Claims = nil
	c.Method = nil
	c.Signature = ""
	c.Raw = ""
	c.Valid = false
	c.Alg = ""
	corePool.Put(c)
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

func ParseWithClaims(tokenString string, claims any, keyFunc func(*Core) (any, error), expectedAlg string) (*Core, error) {
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

	if part3 == "" {
		return nil, errEmptySignature
	}

	alg := DecodeHeaderAlg(part1)
	if alg != "" {
		return parseFastPath(part1, part2, part3, tokenString, alg, claims, keyFunc, expectedAlg)
	}

	return parseSlowPath(part1, part2, part3, tokenString, claims, keyFunc, expectedAlg)
}

// ParseWithClaimsHMAC is a type-specialized variant of ParseWithClaims for HMAC.
// It accepts the HMAC key as []byte directly, avoiding interface boxing overhead
// that causes the key to escape to heap on every call.
func ParseWithClaimsHMAC(tokenString string, claims any, hmacKey []byte, expectedAlg string) (*Core, error) {
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

	if part3 == "" {
		return nil, errEmptySignature
	}

	alg := DecodeHeaderAlg(part1)
	if alg == "" {
		return parseSlowPathHMAC(part1, part2, part3, tokenString, claims, hmacKey, expectedAlg)
	}

	return parseFastPathHMAC(part1, part2, part3, tokenString, alg, claims, hmacKey, expectedAlg)
}

func parseFastPath(part1, part2, part3, tokenString, alg string, claims any, keyFunc func(*Core) (any, error), expectedAlg string) (*Core, error) {
	if expectedAlg != "" && alg != expectedAlg {
		return nil, ErrAlgorithmMismatch
	}
	if isInsecureAlgorithm(alg) {
		return nil, fmt.Errorf("insecure algorithm not allowed: %s", alg)
	}

	method, err := GetInternalSigningMethod(alg)
	if err != nil {
		return nil, err
	}

	if err := DecodeSegment(part2, claims); err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	token := corePool.Get().(*Core)
	token.Raw = tokenString
	token.Signature = part3
	token.Claims = claims
	token.Valid = false
	token.Method = method
	token.Alg = alg

	key, err := keyFunc(token)
	if err != nil {
		ReleaseCore(token)
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	return verifyAndReturn(token, part1, part2, part3, method, key)
}

func parseFastPathHMAC(part1, part2, part3, tokenString, alg string, claims any, hmacKey []byte, expectedAlg string) (*Core, error) {
	if alg != expectedAlg {
		return nil, ErrAlgorithmMismatch
	}
	if isInsecureAlgorithm(alg) {
		return nil, fmt.Errorf("insecure algorithm not allowed: %s", alg)
	}

	method, err := GetInternalSigningMethod(alg)
	if err != nil {
		return nil, err
	}

	if err := DecodeSegment(part2, claims); err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	token := corePool.Get().(*Core)
	token.Raw = tokenString
	token.Signature = part3
	token.Claims = claims
	token.Valid = false
	token.Method = method
	token.Alg = alg

	return verifyAndReturnHMAC(token, part1, part2, part3, method, hmacKey)
}

func parseSlowPath(part1, part2, part3, tokenString string, claims any, keyFunc func(*Core) (any, error), expectedAlg string) (*Core, error) {
	token := corePool.Get().(*Core)
	token.Raw = tokenString
	token.Signature = part3
	token.Claims = claims
	token.Valid = false
	token.Method = nil

	if err := DecodeSegment(part1, &token.Header); err != nil {
		ReleaseCore(token)
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	if len(token.Header) == 0 {
		ReleaseCore(token)
		return nil, errEmptyHeader
	}

	algVal, ok := token.Header["alg"].(string)
	if !ok || algVal == "" {
		ReleaseCore(token)
		return nil, fmt.Errorf("missing or invalid algorithm in header")
	}
	if expectedAlg != "" && algVal != expectedAlg {
		ReleaseCore(token)
		return nil, ErrAlgorithmMismatch
	}
	if isInsecureAlgorithm(algVal) {
		ReleaseCore(token)
		return nil, fmt.Errorf("insecure algorithm not allowed: %s", algVal)
	}

	method, err := GetInternalSigningMethod(algVal)
	if err != nil {
		ReleaseCore(token)
		return nil, err
	}
	token.Method = method
	token.Alg = algVal

	if err := DecodeSegment(part2, claims); err != nil {
		ReleaseCore(token)
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	key, err := keyFunc(token)
	if err != nil {
		ReleaseCore(token)
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	return verifyAndReturn(token, part1, part2, part3, method, key)
}

func parseSlowPathHMAC(part1, part2, part3, tokenString string, claims any, hmacKey []byte, expectedAlg string) (*Core, error) {
	token := corePool.Get().(*Core)
	token.Raw = tokenString
	token.Signature = part3
	token.Claims = claims
	token.Valid = false
	token.Method = nil

	if err := DecodeSegment(part1, &token.Header); err != nil {
		ReleaseCore(token)
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	if len(token.Header) == 0 {
		ReleaseCore(token)
		return nil, errEmptyHeader
	}

	algVal, ok := token.Header["alg"].(string)
	if !ok || algVal == "" {
		ReleaseCore(token)
		return nil, fmt.Errorf("missing or invalid algorithm in header")
	}
	if algVal != expectedAlg {
		ReleaseCore(token)
		return nil, ErrAlgorithmMismatch
	}
	if isInsecureAlgorithm(algVal) {
		ReleaseCore(token)
		return nil, fmt.Errorf("insecure algorithm not allowed: %s", algVal)
	}

	method, err := GetInternalSigningMethod(algVal)
	if err != nil {
		ReleaseCore(token)
		return nil, err
	}
	token.Method = method
	token.Alg = algVal

	if err := DecodeSegment(part2, claims); err != nil {
		ReleaseCore(token)
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	return verifyAndReturnHMAC(token, part1, part2, part3, method, hmacKey)
}

func verifyAndReturn(token *Core, part1, part2, part3 string, method Method, key any) (*Core, error) {
	signingStringLen := len(part1) + 1 + len(part2)

	bufPtr := getParseBuf()
	defer putParseBuf(bufPtr)

	if cap(*bufPtr) < signingStringLen {
		*bufPtr = make([]byte, 0, signingStringLen)
	}

	signingStringBuf := (*bufPtr)[:signingStringLen]
	copy(signingStringBuf, part1)
	signingStringBuf[len(part1)] = '.'
	copy(signingStringBuf[len(part1)+1:], part2)

	signingString := unsafe.String(&signingStringBuf[0], len(signingStringBuf))

	if err := method.Verify(signingString, part3, key); err != nil {
		token.Valid = false
		return token, nil
	}

	token.Valid = true
	return token, nil
}

func verifyAndReturnHMAC(token *Core, part1, part2, part3 string, method Method, hmacKey []byte) (*Core, error) {
	hm, ok := method.(*hmacSigningMethod)
	if !ok {
		return nil, fmt.Errorf("internal error: HMAC parse path used with non-HMAC method %T", method)
	}

	signingStringLen := len(part1) + 1 + len(part2)

	bufPtr := getParseBuf()
	defer putParseBuf(bufPtr)

	if cap(*bufPtr) < signingStringLen {
		*bufPtr = make([]byte, 0, signingStringLen)
	}

	signingStringBuf := (*bufPtr)[:signingStringLen]
	copy(signingStringBuf, part1)
	signingStringBuf[len(part1)] = '.'
	copy(signingStringBuf[len(part1)+1:], part2)

	signingString := unsafe.String(&signingStringBuf[0], len(signingStringBuf))

	if err := hm.VerifyHMAC(signingString, part3, hmacKey); err != nil {
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
	if _, ok := insecureAlgorithms[alg]; ok {
		return true
	}
	for insecure := range insecureAlgorithms {
		if len(insecure) > 0 && equalFoldASCII(trimSpaceBytes(alg), insecure) {
			return true
		}
	}
	return false
}

func trimSpaceBytes(s string) string {
	start, end := 0, len(s)
	for start < end && s[start] == ' ' {
		start++
	}
	for end > start && s[end-1] == ' ' {
		end--
	}
	return s[start:end]
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
