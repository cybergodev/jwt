package internal

import (
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

	if part3 == "" {
		return nil, errEmptySignature
	}

	// Fast path: extract algorithm without full JSON decode of header.
	// This avoids map[string]any allocation for the happy path since
	// we only need alg for method lookup and keyFunc typically only reads alg.
	alg := DecodeHeaderAlg(part1)
	if alg != "" {
		return parseFastPath(part1, part2, part3, tokenString, alg, claims, keyFunc)
	}

	// Slow path: full header decode for malformed/unusual headers
	return parseSlowPath(part1, part2, part3, tokenString, claims, keyFunc)
}

func parseFastPath(part1, part2, part3, tokenString, alg string, claims any, keyFunc func(*Core) (any, error)) (*Core, error) {
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

	// Set only the "alg" field in the header map. keyFunc reads only "alg",
	// so we skip full JSON decode to avoid interface boxing allocations.
	token.Header["alg"] = alg

	key, err := keyFunc(token)
	if err != nil {
		ReleaseCore(token)
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	return verifyAndReturn(token, part1, part2, part3, method, key)
}

func parseSlowPath(part1, part2, part3, tokenString string, claims any, keyFunc func(*Core) (any, error)) (*Core, error) {
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

	// SAFETY: signingString references bufPtr's pooled memory, valid until
	// deferred putParseBuf returns it to the pool. method.Verify only reads
	// the string and does not retain a reference after returning.
	signingString := unsafe.String(&signingStringBuf[0], len(signingStringBuf))

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
	if _, ok := insecureAlgorithms[alg]; ok {
		return true
	}
	// Slow path: byte-level case-insensitive comparison without allocation.
	// Only reached for non-standard algorithm strings.
	for insecure := range insecureAlgorithms {
		if len(insecure) > 0 && equalFoldASCII(trimSpaceBytes(alg), insecure) {
			return true
		}
	}
	return false
}

// trimSpaceBytes trims leading and trailing ASCII spaces without allocation.
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

// equalFoldASCII reports whether a and b are equal under ASCII case-folding.
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
