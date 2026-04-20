package internal

import (
	"fmt"
	"strings"
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

// corePool pools Core structs to reduce allocations during token parsing.
var corePool = sync.Pool{
	New: func() any {
		return &Core{
			Header: make(map[string]any, 2),
		}
	},
}

// GetCore retrieves a Core struct from the pool.
func GetCore() *Core {
	return corePool.Get().(*Core)
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

	// Explicitly check for empty signature
	if part3 == "" {
		return nil, errEmptySignature
	}

	token := corePool.Get().(*Core)
	token.Raw = tokenString
	token.Signature = part3
	token.Claims = claims
	token.Valid = false
	token.Method = nil

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

	bufPtr := getParseBuf()
	defer putParseBuf(bufPtr)

	if cap(*bufPtr) < signingStringLen {
		*bufPtr = make([]byte, 0, signingStringLen)
	}

	signingStringBuf := (*bufPtr)[:signingStringLen]
	copy(signingStringBuf, part1)
	signingStringBuf[len(part1)] = '.'
	copy(signingStringBuf[len(part1)+1:], part2)

	// Use unsafe string for internal Verify call (safe: buffer not returned to pool until after Verify returns)
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
	normalized := strings.ToUpper(strings.TrimSpace(alg))
	_, exists := insecureAlgorithms[normalized]
	return exists
}

func (t *Core) SignedString(key any) (string, error) {
	return SignedString(t.Header, t.Claims, t.Method, key)
}
