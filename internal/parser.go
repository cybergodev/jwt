package internal

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"unsafe"
)

const (
	// maxTokenLength caps the total token string (header.payload.signature).
	// Only the payload segment can approach maxSegmentLength; the header is
	// tiny (~40 bytes) and signatures peak at 684 bytes (RSA-4096), so a value
	// well above one full payload segment suffices as a DoS guard.
	maxTokenLength = 131072
)

var (
	errEmptyToken         = errors.New("empty token")
	errTokenTooLarge      = fmt.Errorf("token too large: maximum %d characters allowed", maxTokenLength)
	errInvalidTokenFormat = errors.New("invalid token format: expected 3 parts separated by dots")
	errEmptyHeader        = errors.New("empty header: JWT must have a valid header")
	errEmptySignature     = errors.New("empty signature: JWT must have a valid signature")

	// ErrAlgorithmMismatch indicates that the token's algorithm does not match
	// the expected signing method.
	ErrAlgorithmMismatch = errors.New("token algorithm does not match configured signing method")
)

// errFastPathFallback signals that the fast path's cheaply-scanned alg could
// not be trusted (mismatch, unresolvable or insecure method, claims decode
// error) and the caller should retry via the slow path's full header decode.
// The DecodeHeaderAlg scan is not JSON-structure-aware: a legal header whose
// nested object contains an "alg" key before the real one yields a bogus
// fast alg, and only the slow path can adjudicate such headers. Genuine
// mismatches are re-derived (and re-reported) by the slow path, so only
// malformed-input paths pay the extra decode.
var errFastPathFallback = errors.New("fast path inapplicable")

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
	c.Signature = ""
	c.Raw = ""
	c.Valid = false
	c.Alg = ""
	corePool.Put(c)
}

// newPooledCore takes a Core from the pool and fills the fields shared by
// every parse path. alg may be empty when the path derives it later from the
// decoded header (the slow paths, via decodeHeaderAndClaims).
func newPooledCore(tokenString, signature, alg string, claims any) *Core {
	token := corePool.Get().(*Core)
	token.Raw = tokenString
	token.Signature = signature
	token.Claims = claims
	token.Valid = false
	token.Alg = alg
	return token
}

// fastSplit3 splits s on the first two occurrences of sep, returning the three
// surrounding substrings. It uses strings.IndexByte, whose amd64/arm64
// implementations are SIMD-vectorized and scan far faster than a byte-by-byte
// loop — this runs on every parse, and profiling showed the manual loop among
// the validate path's CPU hotspots. Semantics match the previous loop: exactly
// two separators yield ok=true; fewer yield ok=false (and part3 == "" when the
// token ends with its second dot, which callers reject as an empty signature).
func fastSplit3(s string, sep byte) (string, string, string, bool) {
	first := strings.IndexByte(s, sep)
	if first < 0 {
		return "", "", "", false
	}
	second := strings.IndexByte(s[first+1:], sep)
	if second < 0 {
		return "", "", "", false
	}
	second += first + 1
	return s[:first], s[first+1 : second], s[second+1:], true
}

// splitToken applies the entry-point guards shared by ParseWithClaims and
// ParseWithClaimsHMAC: it rejects empty and oversized tokens, splits on the
// first two dots, and rejects an empty signature segment. The returned parts
// are reslices of tokenString, so no allocation is added on the hot path.
func splitToken(tokenString string) (string, string, string, error) {
	if len(tokenString) == 0 {
		return "", "", "", errEmptyToken
	}
	if len(tokenString) > maxTokenLength {
		return "", "", "", errTokenTooLarge
	}
	part1, part2, part3, ok := fastSplit3(tokenString, '.')
	if !ok {
		return "", "", "", errInvalidTokenFormat
	}
	if part3 == "" {
		return "", "", "", errEmptySignature
	}
	return part1, part2, part3, nil
}

// ParseWithClaims splits, decodes, and signature-verifies tokenString, writing
// the decoded payload into claims. keyFunc resolves the verification key for the
// token's algorithm (and may reject it); expectedAlg is the single accepted alg.
// The returned Core is pooled and must be released with ReleaseCore.
func ParseWithClaims(tokenString string, claims any, keyFunc func(*Core) (any, error), expectedAlg string) (*Core, error) {
	part1, part2, part3, err := splitToken(tokenString)
	if err != nil {
		return nil, err
	}

	alg := DecodeHeaderAlg(part1)
	if alg != "" {
		if core, err := parseFastPath(part1, part2, part3, tokenString, alg, claims, keyFunc, expectedAlg); err != errFastPathFallback {
			return core, err
		}
	}

	return parseSlowPath(part1, part2, part3, tokenString, claims, keyFunc, expectedAlg)
}

// ParseWithClaimsHMAC is a type-specialized variant of ParseWithClaims for HMAC.
// It accepts the HMAC key as []byte directly, avoiding interface boxing overhead
// that causes the key to escape to heap on every call.
func ParseWithClaimsHMAC(tokenString string, claims any, hmacKey []byte, expectedAlg string) (*Core, error) {
	part1, part2, part3, err := splitToken(tokenString)
	if err != nil {
		return nil, err
	}

	alg := DecodeHeaderAlg(part1)
	if alg != "" {
		if core, err := parseFastPathHMAC(part1, part2, part3, tokenString, alg, claims, hmacKey, expectedAlg); err != errFastPathFallback {
			return core, err
		}
	}

	return parseSlowPathHMAC(part1, part2, part3, tokenString, claims, hmacKey, expectedAlg)
}

func parseFastPath(part1, part2, part3, tokenString, alg string, claims any, keyFunc func(*Core) (any, error), expectedAlg string) (*Core, error) {
	method, err := resolveFastClaims(alg, expectedAlg, expectedAlg != "", part2, claims)
	if err != nil {
		// The fast alg scan may have misread a structurally-legal header;
		// defer to the slow path (see errFastPathFallback).
		return nil, errFastPathFallback
	}

	token := newPooledCore(tokenString, part3, alg, claims)

	key, err := keyFunc(token)
	if err != nil {
		ReleaseCore(token)
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	return verifyAndReturn(token, part1, part2, part3, method, key)
}

func parseFastPathHMAC(part1, part2, part3, tokenString, alg string, claims any, hmacKey []byte, expectedAlg string) (*Core, error) {
	// HMAC always enforces alg-match (ParseWithClaimsHMAC is the sole caller and
	// always passes the configured method), so enforceAlg is hard-coded true.
	method, err := resolveFastClaims(alg, expectedAlg, true, part2, claims)
	if err != nil {
		// See errFastPathFallback: let the slow path re-derive the alg.
		return nil, errFastPathFallback
	}

	token := newPooledCore(tokenString, part3, alg, claims)

	return verifyAndReturnHMAC(token, part1, part2, part3, method, hmacKey)
}

// resolveFastClaims runs the fast-path steps shared by the generic and HMAC
// parsers before a Core is pooled: validate the cheaply-extracted alg, resolve its
// Method, and decode the claims segment. enforceAlg reproduces the two callers'
// alg-match guards: the generic path passes expectedAlg != "" (so an empty
// expectedAlg skips the check), the HMAC path passes true unconditionally.
func resolveFastClaims(alg, expectedAlg string, enforceAlg bool, part2 string, claims any) (Method, error) {
	if enforceAlg && alg != expectedAlg {
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

	return method, nil
}

func parseSlowPath(part1, part2, part3, tokenString string, claims any, keyFunc func(*Core) (any, error), expectedAlg string) (*Core, error) {
	token := newPooledCore(tokenString, part3, "", claims)

	method, err := decodeHeaderAndClaims(token, part1, part2, expectedAlg, expectedAlg != "")
	if err != nil {
		ReleaseCore(token)
		return nil, err
	}

	key, err := keyFunc(token)
	if err != nil {
		ReleaseCore(token)
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	return verifyAndReturn(token, part1, part2, part3, method, key)
}

func parseSlowPathHMAC(part1, part2, part3, tokenString string, claims any, hmacKey []byte, expectedAlg string) (*Core, error) {
	token := newPooledCore(tokenString, part3, "", claims)

	// HMAC always enforces alg-match (see resolveFastClaims), so enforceAlg is
	// hard-coded true.
	method, err := decodeHeaderAndClaims(token, part1, part2, expectedAlg, true)
	if err != nil {
		ReleaseCore(token)
		return nil, err
	}

	return verifyAndReturnHMAC(token, part1, part2, part3, method, hmacKey)
}

// decodeHeaderAndClaims runs the slow-path header/claims handling shared by the
// generic and HMAC parsers: decode the header, validate it is non-empty,
// extract and validate the alg (with the caller-controlled alg-match guard),
// reject insecure algs, resolve the Method, cache it as token.Alg, then decode
// the claims. enforceAlg reproduces the two callers' guards: the generic path
// passes expectedAlg != "", the HMAC path passes true unconditionally. The
// helper does NOT release token on error — the caller owns the pooled Core and
// is responsible for ReleaseCore on any returned error.
func decodeHeaderAndClaims(token *Core, part1, part2, expectedAlg string, enforceAlg bool) (Method, error) {
	if err := DecodeSegment(part1, &token.Header); err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	if len(token.Header) == 0 {
		return nil, errEmptyHeader
	}

	algVal, ok := token.Header["alg"].(string)
	if !ok || algVal == "" {
		return nil, fmt.Errorf("missing or invalid algorithm in header")
	}
	if enforceAlg && algVal != expectedAlg {
		return nil, ErrAlgorithmMismatch
	}
	if isInsecureAlgorithm(algVal) {
		return nil, fmt.Errorf("insecure algorithm not allowed: %s", algVal)
	}

	method, err := GetInternalSigningMethod(algVal)
	if err != nil {
		return nil, err
	}
	token.Alg = algVal

	if err := DecodeSegment(part2, token.Claims); err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	return method, nil
}

func verifyAndReturn(token *Core, part1, part2, part3 string, method Method, key any) (*Core, error) {
	bufPtr := getParseBuf()
	defer putParseBuf(bufPtr)

	signingString := buildSigningString(part1, part2, bufPtr)

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
		// Unreachable via the public paths (the method was resolved by alg);
		// still return the pooled Core rather than dropping it.
		ReleaseCore(token)
		return nil, fmt.Errorf("internal error: HMAC parse path used with non-HMAC method %T", method)
	}

	bufPtr := getParseBuf()
	defer putParseBuf(bufPtr)

	signingString := buildSigningString(part1, part2, bufPtr)

	if err := hm.VerifyHMAC(signingString, part3, hmacKey); err != nil {
		token.Valid = false
		return token, nil
	}

	token.Valid = true
	return token, nil
}

// buildSigningString writes "part1.part2" into bufPtr's pooled capacity and returns
// it as a string that aliases the buffer. The caller owns bufPtr (from getParseBuf)
// and must keep it live — and must not return it to the pool — until it is done
// reading the returned string. Precondition: part1 and part2 are non-empty
// (guaranteed by the parse entry points, which reject malformed/empty-segment
// tokens upstream), so signingStringLen > 0 and &signingStringBuf[0] is in range.
func buildSigningString(part1, part2 string, bufPtr *[]byte) string {
	signingStringLen := len(part1) + 1 + len(part2)

	if cap(*bufPtr) < signingStringLen {
		*bufPtr = make([]byte, 0, signingStringLen)
	}

	signingStringBuf := (*bufPtr)[:signingStringLen]
	copy(signingStringBuf, part1)
	signingStringBuf[len(part1)] = '.'
	copy(signingStringBuf[len(part1)+1:], part2)

	return unsafe.String(&signingStringBuf[0], len(signingStringBuf))
}

// ParseUnverified decodes tokenString into claims without checking its
// signature, returning the parsed Core and the raw header map. Intended only
// for inspection/logging; callers must never trust the result for auth.
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
	// Fast path: every algorithm in the read-only method registry (globalMethods,
	// populated once in init()) is cryptographically sound, and these account for
	// essentially every real token. A single map lookup lets the common case skip
	// the case-insensitive scan below — profiling showed that scan alone was a
	// notable validate-path cost, because a valid alg like "HS256" misses the
	// insecureAlgorithms map and then runs equalFoldASCII against all 11 entries.
	// No insecure algorithm is ever registered, so this short-circuit cannot
	// weaken the check.
	if _, ok := globalMethods[alg]; ok {
		return false
	}
	if _, ok := insecureAlgorithms[alg]; ok {
		return true
	}
	// The trimmed value is invariant across iterations, so compute it once
	// instead of re-scanning alg (O(n)) on every loop iteration.
	trimmed := trimSpaceBytes(alg)
	for insecure := range insecureAlgorithms {
		if len(insecure) > 0 && equalFoldASCII(trimmed, insecure) {
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
