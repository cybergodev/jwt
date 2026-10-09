package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"unsafe"
)

const (
	// maxDecodedSize caps the decoded size of a single JWT segment (header or
	// payload). It is a DoS guard and MUST be large enough to hold the largest
	// payload the package's own validation allows (see jwt.maxArraySize /
	// jwt.maxStringLength / jwt.maxExtraSize), otherwise tokens that pass Create
	// would be unparseable by Validate. 64 KiB covers realistic claim sets
	// (e.g. 100 permissions of 256 bytes) with headroom.
	maxDecodedSize = 65536
	// maxSegmentLength is the base64url-encoded counterpart of maxDecodedSize
	// (EncodedLen(65536) == 87382), plus a small margin.
	maxSegmentLength = 87384
)

// decodeBufPool pools byte slices for base64 decoding operations.
// JWT segments are typically small (< 512 bytes), so we use a reasonable
// initial capacity to reduce allocations while avoiding waste.
var decodeBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 512)
		return &buf
	},
}

func getDecodeBuf() *[]byte {
	return decodeBufPool.Get().(*[]byte)
}

func putDecodeBuf(buf *[]byte) {
	if cap(*buf) <= 2048 {
		*buf = (*buf)[:0]
		decodeBufPool.Put(buf)
	}
}

// stringToBytes converts a string to a byte slice without allocation.
// The returned byte slice must not be modified — the underlying data is
// shared with the source string. Safe for read-only use in base64/hashing.
// Uses unsafe for zero allocation conversion.
func stringToBytes(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// FastUnmarshaler is implemented by claims types that decode their own JSON
// with a hand-written scanner (the built-in jwt.Claims does). DecodeSegment
// tries it before encoding/json: on success the payload is scanned once
// instead of three times (encoding/json's validity pre-scan, its literal
// skip pass, and the custom decoder itself), which profiling showed was the
// dominant cost of the validate path. Any non-nil error means the
// implementation declined or failed, and DecodeSegment MUST then re-derive
// the result via encoding/json, which owns the authoritative decoded values
// and error values.
//
// Nil-receiver contract: a typed-nil pointer boxes as a non-nil interface
// value and therefore reaches UnmarshalFastJSON. Implementations with pointer
// receivers MUST return an error in that case (the built-in *Claims declines,
// letting encoding/json emit its canonical InvalidUnmarshalError) — writing
// through the receiver would panic.
type FastUnmarshaler interface {
	// UnmarshalFastJSON decodes data into the receiver. On any error the
	// receiver's contents are unspecified; the caller must re-decode with
	// encoding/json.
	UnmarshalFastJSON(data []byte) error
}

// DecodeSegment base64url-decodes a single JWT segment (header or payload) and
// JSON-unmarshals the result into dest. Empty or oversized segments are rejected
// as a DoS guard (see maxSegmentLength / maxDecodedSize).
//
// The decoded bytes are pooled (decodeBufPool), not stack-allocated: data flows
// into the FastUnmarshaler interface call, which defeats escape analysis and
// would force a per-call heap allocation of a stack buffer (measured: one
// extra alloc and +1 KiB/op per parse when tried).
func DecodeSegment(segment string, dest any) error {
	segLen := len(segment)
	if segLen == 0 {
		return fmt.Errorf("empty segment")
	}
	if segLen > maxSegmentLength {
		return fmt.Errorf("segment too large: %d bytes exceeds maximum %d", segLen, maxSegmentLength)
	}

	bufLen := base64.RawURLEncoding.DecodedLen(segLen)
	if bufLen > maxDecodedSize {
		return fmt.Errorf("decoded segment too large: %d bytes exceeds maximum %d", bufLen, maxDecodedSize)
	}

	bufPtr := getDecodeBuf()
	defer putDecodeBuf(bufPtr)

	// Grow buffer if needed
	if cap(*bufPtr) < bufLen {
		*bufPtr = make([]byte, 0, bufLen)
	}

	buf := (*bufPtr)[:bufLen]
	n, err := base64.RawURLEncoding.Decode(buf, stringToBytes(segment))
	if err != nil {
		return fmt.Errorf("base64 decode failed: %w", err)
	}

	data := buf[:n]
	if fu, ok := dest.(FastUnmarshaler); ok {
		if err := fu.UnmarshalFastJSON(data); err == nil {
			return nil
		}
		// Fast decode declined: fall through to encoding/json, which re-derives
		// the authoritative result (decoded values and error values alike).
	}

	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("json unmarshal failed: %w", err)
	}

	return nil
}

// headerStackBuf is the decoded-size budget for the common JWT header
// ({"alg":"HS256","typ":"JWT"} decodes to 27 bytes); headers within it are
// base64-decoded into a stack buffer, skipping two sync.Pool round-trips per
// parse. Larger (rare) headers fall back to the pooled buffer.
const headerStackBuf = 128

// DecodeHeaderAlg extracts the "alg" field from a base64url-encoded JWT header
// without fully decoding the header into a map. Returns empty string if alg is
// not found or if the header is invalid.
// This avoids map[string]any allocation and interface boxing for the common case
// where only the algorithm is needed.
func DecodeHeaderAlg(headerSegment string) string {
	segLen := len(headerSegment)
	if segLen == 0 || segLen > maxSegmentLength {
		return ""
	}

	bufLen := base64.RawURLEncoding.DecodedLen(segLen)
	if bufLen > maxDecodedSize {
		return ""
	}

	var stack [headerStackBuf]byte
	var buf []byte
	if bufLen <= headerStackBuf {
		buf = stack[:bufLen]
	} else {
		bufPtr := getDecodeBuf()
		defer putDecodeBuf(bufPtr)

		if cap(*bufPtr) < bufLen {
			*bufPtr = make([]byte, 0, bufLen)
		}
		buf = (*bufPtr)[:bufLen]
	}

	n, err := base64.RawURLEncoding.Decode(buf, stringToBytes(headerSegment))
	if err != nil {
		return ""
	}

	data := buf[:n]
	// Fast scan for "alg":"<value>" pattern in the JSON
	// JWT headers are small and simple: {"alg":"HS256","typ":"JWT"}
	return extractAlgFromJSON(data)
}

// internedAlgs maps the byte form of each standard JWT algorithm to its
// canonical string. Returning the constant string (rather than allocating a
// fresh one from the decoded bytes) removes one allocation per validated token,
// since every standard token carries one of these algorithms in its header.
var internedAlgs = map[[5]byte]string{
	{'H', 'S', '2', '5', '6'}: "HS256",
	{'H', 'S', '3', '8', '4'}: "HS384",
	{'H', 'S', '5', '1', '2'}: "HS512",
	{'R', 'S', '2', '5', '6'}: "RS256",
	{'R', 'S', '3', '8', '4'}: "RS384",
	{'R', 'S', '5', '1', '2'}: "RS512",
	{'P', 'S', '2', '5', '6'}: "PS256",
	{'P', 'S', '3', '8', '4'}: "PS384",
	{'P', 'S', '5', '1', '2'}: "PS512",
	{'E', 'S', '2', '5', '6'}: "ES256",
	{'E', 'S', '3', '8', '4'}: "ES384",
	{'E', 'S', '5', '1', '2'}: "ES512",
}

// internAlg returns the canonical string for a known 5-character JWT algorithm
// without allocating, falling back to string(b) for anything unrecognized. The
// standard algorithms are all exactly 5 bytes (two letters + three digits), so
// the lookup hits on essentially every real token.
func internAlg(b []byte) string {
	if len(b) == 5 {
		var k [5]byte
		copy(k[:], b)
		if s, ok := internedAlgs[k]; ok {
			return s
		}
	}
	return string(b)
}

// extractAlgFromJSON scans the JSON data for the "alg" field value.
// Handles both {"alg":"HS256","typ":"JWT"} and {"typ":"JWT","alg":"HS256"}.
// Skips over JSON string values when scanning for the key, preventing
// false matches from "alg" embedded inside string values.
func extractAlgFromJSON(data []byte) string {
	idx := 0
	for idx+4 <= len(data) {
		// Direct byte comparison for "alg" key pattern
		if data[idx] == '"' && data[idx+1] == 'a' && data[idx+2] == 'l' && data[idx+3] == 'g' {
			// Look ahead: a JSON key must be followed by closing quote then colon
			pos := idx + 4
			if pos < len(data) && data[pos] == '"' {
				pos++ // skip closing quote
				// Skip whitespace before colon
				for pos < len(data) && data[pos] == ' ' {
					pos++
				}
				if pos < len(data) && data[pos] == ':' {
					pos++ // skip colon
					// Skip whitespace before value
					for pos < len(data) && data[pos] == ' ' {
						pos++
					}
					if pos < len(data) && data[pos] == '"' {
						pos++ // skip opening quote
						start := pos
						for pos < len(data) {
							if data[pos] == '\\' {
								pos += 2
								continue
							}
							if data[pos] == '"' {
								break
							}
							pos++
						}
						if pos < len(data) {
							return internAlg(data[start:pos])
						}
					}
				}
			}
			// Not a key — skip past this string
			idx++
			continue
		}
		// Skip other string values to avoid false "alg" matches inside values
		if data[idx] == '"' {
			idx = skipJSONString(data, idx)
			continue
		}
		idx++
	}
	return ""
}

// skipJSONString advances past a JSON string starting at the opening quote (data[idx] == '"').
// Returns the index after the closing quote.
func skipJSONString(data []byte, idx int) int {
	if idx >= len(data) || data[idx] != '"' {
		return idx + 1
	}
	idx++ // skip opening quote
	for idx < len(data) {
		if data[idx] == '\\' {
			idx += 2 // skip escaped character
			continue
		}
		if data[idx] == '"' {
			return idx + 1 // past closing quote
		}
		idx++
	}
	return idx
}
