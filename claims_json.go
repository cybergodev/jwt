package jwt

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"sync"
	"unsafe"
)

// This file provides specialized JSON encoding and decoding for the built-in
// Claims type. Profiling showed encoding/json's reflection-based machinery
// dominating both hot paths (~49% of Create CPU, ~48% of Validate CPU, and
// every allocation on the parse path).
//
// Safety contract: both directions defer to encoding/json for anything they
// cannot reproduce byte-for-byte.
//
//   - Encoding: the fast appender writes fields directly only when their
//     content provably needs no JSON escaping; anything else (non-ASCII,
//     quotes, backslashes, HTML-significant bytes, non-string Extra values)
//     is delegated to encoding/json per value.
//   - Decoding: the object scanner validates JSON structure strictly and
//     bails out — falling back to a full encoding/json decode — on every
//     form it does not fully understand (escaped keys or string values,
//     non-string scalars where a type error is required, unusual numbers,
//     nesting past encoding/json's depth limit, trailing garbage, ...).
//     The fallback re-derives the authoritative result, so observable
//     behavior (decoded values AND error values) stays identical to
//     encoding/json's. Differential tests and a fuzz target in
//     claims_json_test.go pin this equivalence.
//
// The append-style entry point (AppendJSON) additionally lets the signing
// pipeline encode claims straight into its pooled buffer, skipping the
// marshal-then-copy pass the json.Encoder performs.
//
// Decoded strings are copied into per-structure "slabs" (see slabString):
// one shared allocation replaces one per string, and the copies are just as
// private as individually allocated strings — the source bytes live in
// pooled buffers that are reused after the decode.

// errClaimsJSONFallback tells UnmarshalJSON that the fast scanner could not
// handle the input and the fallback decode should run.
var errClaimsJSONFallback = errors.New("claims JSON fast path inapplicable")

// AppendJSON appends the JSON encoding of the claims to dst and returns the
// extended slice. The output is byte-for-byte identical to
// json.Marshal(*Claims); the method exists so the signing pipeline (and other
// allocation-sensitive callers) can encode into a reusable buffer instead of
// allocating a fresh one per token. The result is only appended to; existing
// bytes in dst are never rewritten.
//
// Advanced API: most callers should rely on MarshalJSON (used automatically
// by encoding/json) and never call this method directly.
func (c *Claims) AppendJSON(dst []byte) ([]byte, error) {
	dst = append(dst, '{')

	// str emits `,"key":"value"` for a non-empty string field. Both captured
	// variables (dst, first) are closed over by reference, so the writes are
	// visible to the code after the closure.
	first := true
	str := func(key, value string) {
		if value == "" {
			return
		}
		if !first {
			dst = append(dst, ',')
		}
		first = false
		dst = append(dst, '"')
		dst = append(dst, key...)
		dst = append(dst, `":`...)
		dst = appendJSONString(dst, value)
	}

	// Field order matches encoding/json: declaration order, with the embedded
	// RegisteredClaims inline at its declaration position.
	str("user_id", c.UserID)
	str("username", c.Username)
	str("role", c.Role)

	if len(c.Permissions) > 0 {
		if !first {
			dst = append(dst, ',')
		}
		first = false
		dst = append(dst, `"permissions":[`...)
		dst = appendJSONStringSlice(dst, c.Permissions)
		dst = append(dst, ']')
	}
	if len(c.Scopes) > 0 {
		if !first {
			dst = append(dst, ',')
		}
		first = false
		dst = append(dst, `"scopes":[`...)
		dst = appendJSONStringSlice(dst, c.Scopes)
		dst = append(dst, ']')
	}
	if len(c.Extra) > 0 {
		if !first {
			dst = append(dst, ',')
		}
		first = false
		var err error
		dst, err = appendExtra(dst, c.Extra)
		if err != nil {
			return dst, err
		}
	}

	str("session_id", c.SessionID)
	str("client_id", c.ClientID)
	str("iss", c.Issuer)
	str("sub", c.Subject)

	switch len(c.Audience) {
	case 0:
		// omitempty: nothing to emit.
	case 1:
		// RFC 7519 §4.1.3: a single audience serializes as a bare string.
		if !first {
			dst = append(dst, ',')
		}
		first = false
		dst = append(dst, `"aud":`...)
		dst = appendJSONString(dst, c.Audience[0])
	default:
		if !first {
			dst = append(dst, ',')
		}
		first = false
		dst = append(dst, `"aud":[`...)
		dst = appendJSONStringSlice(dst, c.Audience)
		dst = append(dst, ']')
	}

	// exp/nbf/iat have no omitempty: encoding/json always emits them (as
	// null for the zero time), so the wire format stays unchanged. exp is
	// therefore always present, and everything after it takes a comma.
	if !first {
		dst = append(dst, ',')
	}
	first = false
	dst = append(dst, `"exp":`...)
	dst = appendNumericDate(dst, c.ExpiresAt)
	dst = append(dst, `,"nbf":`...)
	dst = appendNumericDate(dst, c.NotBefore)
	dst = append(dst, `,"iat":`...)
	dst = appendNumericDate(dst, c.IssuedAt)

	str("jti", c.ID)
	str("token_type", c.TokenType)

	return append(dst, '}'), nil
}

// MarshalJSON implements json.Marshaler. The output is identical to what
// encoding/json's reflection path produced before this method existed
// (verified by differential tests), including field order, omitempty
// behavior, map-key sorting, and string escaping.
//
// The receiver is a pointer: the signing pipeline always marshals through
// pointers. Marshaling a non-addressable Claims value falls back to
// encoding/json's reflection path, whose output is the same.
func (c *Claims) MarshalJSON() ([]byte, error) {
	return c.AppendJSON(make([]byte, 0, 256))
}

// UnmarshalJSON implements json.Unmarshaler. It scans the payload with a
// strict, allocation-light object scanner and fills the known fields
// directly; any input the scanner cannot fully verify is re-decoded by
// encoding/json, which owns the authoritative semantics (exact decoded
// values and exact error values).
func (c *Claims) UnmarshalJSON(data []byte) error {
	if err := c.unmarshalFast(data); err == nil {
		return nil
	}
	// Fast path declined (structural doubt or a field-level error): re-derive
	// everything via encoding/json. claimsAlias has no methods, so the
	// decode is pure reflection and cannot recurse into UnmarshalJSON.
	// Fields the fast path already set are re-set identically by this pass,
	// so the partial mutation is harmless.
	//
	// Note: the fast path returns no errors of its own — every failure
	// routes here — so UnmarshalJSON's observable errors are always
	// encoding/json's.
	type claimsAlias Claims
	return json.Unmarshal(data, (*claimsAlias)(c))
}

// UnmarshalFastJSON runs the strict fast scanner directly on a decoded JWT
// payload. It implements the internal decode hook (FastUnmarshaler) so the
// parse pipeline can call the scanner without encoding/json's validity
// pre-scan and literal-skip pass around it.
//
// Contract: any non-nil error (most commonly the internal fallback sentinel)
// obligates the caller to re-derive the result with encoding/json, whose
// semantics are authoritative; the receiver's contents are then unspecified.
//
// Advanced API: most callers should rely on UnmarshalJSON — which enforces
// exactly this fast-then-fallback sequence — and never call this method
// directly.
func (c *Claims) UnmarshalFastJSON(data []byte) error {
	return c.unmarshalFast(data)
}

// extraKeysPool holds scratch slices for appendExtra's sorted-key iteration,
// replacing one allocation per Create (and MarshalJSON) call that carries an
// Extra map.
var extraKeysPool = sync.Pool{
	New: func() any {
		s := make([]string, 0, maxExtraSize)
		return &s
	},
}

// appendExtra appends the "extra" object. Keys are sorted (matching
// encoding/json's deterministic map encoding); values take a fast path for
// the types the library documents for Extra (string, string slice) plus the
// trivial scalars, and defer to json.Marshal for everything else so their
// encoding stays exactly the standard library's.
func appendExtra(dst []byte, extra map[string]any) ([]byte, error) {
	dst = append(dst, `"extra":{`...)
	// Exact-capacity key collection: an iterator (maps.Keys) cannot size its
	// destination slice, so slices.Sorted grows it; collecting into a pooled
	// scratch slice allocates nothing for validated maps (≤ maxExtraSize keys).
	keysPtr := extraKeysPool.Get().(*[]string)
	keys := (*keysPtr)[:0]
	for k := range extra {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	// Oversized slices (an unvalidated Extra beyond maxExtraSize, possible
	// via direct json.Marshal use) are dropped rather than pinned in the pool.
	if cap(keys) <= maxExtraSize*2 {
		defer func() {
			*keysPtr = keys[:0]
			extraKeysPool.Put(keysPtr)
		}()
	}
	first := true
	for _, k := range keys {
		if !first {
			dst = append(dst, ',')
		}
		first = false
		dst = appendJSONString(dst, k)
		dst = append(dst, ':')
		switch v := extra[k].(type) {
		case nil:
			dst = append(dst, `null`...)
		case bool:
			dst = strconv.AppendBool(dst, v)
		case string:
			dst = appendJSONString(dst, v)
		case []string:
			if v == nil {
				dst = append(dst, `null`...)
			} else {
				dst = append(dst, '[')
				dst = appendJSONStringSlice(dst, v)
				dst = append(dst, ']')
			}
		case int:
			dst = strconv.AppendInt(dst, int64(v), 10)
		case int64:
			dst = strconv.AppendInt(dst, v, 10)
		default:
			b, err := json.Marshal(v)
			if err != nil {
				return dst, err
			}
			dst = append(dst, b...)
		}
	}
	return append(dst, '}'), nil
}

// appendJSONStringSlice appends the elements of items as a JSON array body
// (no enclosing brackets).
func appendJSONStringSlice(dst []byte, items []string) []byte {
	for i, item := range items {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONString(dst, item)
	}
	return dst
}

// jsonSafeASCII marks the single bytes encoding/json copies through verbatim
// inside a string literal: printable ASCII (0x20-0x7e) outside " \ < > &.
// Everything else — control bytes (incl. 0x7f, which encoding/json escapes as
// \u007f), non-ASCII that might need \uXXXX escaping, quote/backslash, and
// the HTML-significant trio — defers to json.Marshal. A single table load
// replaces the seven-way comparison chain per byte.
var jsonSafeASCII = func() [256]bool {
	var t [256]bool
	for c := 0x20; c < 0x7f; c++ {
		t[c] = true
	}
	t['"'] = false
	t['\\'] = false
	t['<'] = false
	t['>'] = false
	t['&'] = false
	return t
}()

// appendJSONString appends s as a quoted JSON string. The fast path appends
// directly when s contains only printable ASCII outside " \ < > & — bytes
// encoding/json would copy through verbatim. Any other content (control
// bytes, non-ASCII that might need \uXXXX escaping, quote/backslash, the
// HTML-significant trio) defers to json.Marshal so escaping stays
// byte-for-byte identical to the standard library's.
func appendJSONString(dst []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		if !jsonSafeASCII[s[i]] {
			// json.Marshal on a string cannot fail (the only marshal errors
			// come from channels, cycles, and NaN/Inf, none representable in
			// a string); the error is therefore deliberately not surfaced.
			b, _ := json.Marshal(s)
			return append(dst, b...)
		}
	}
	dst = append(dst, '"')
	dst = append(dst, s...)
	return append(dst, '"')
}

// appendNumericDate appends d's JSON form: the Unix timestamp for in-range
// values, null for the zero time and out-of-range values — the same rules as
// NumericDate.MarshalJSON, without that method's heap-returned buffer.
func appendNumericDate(dst []byte, d NumericDate) []byte {
	if d.IsZero() {
		return append(dst, `null`...)
	}
	unix := d.Unix()
	if unix < 0 || unix > maxValidTimestamp {
		return append(dst, `null`...)
	}
	return strconv.AppendInt(dst, unix, 10)
}

// claimKeyBufSize is the length of the longest Claims JSON key
// ("permissions"). Longer object keys cannot name a Claims field.
const claimKeyBufSize = len("permissions")

// maxJSONDepth mirrors encoding/json's nesting limit (10000); deeper input
// errors there, so the scanner declines and lets the fallback produce that
// error rather than recursing further itself.
const maxJSONDepth = 10000

// unmarshalFast scans data as a flat JSON object and fills c's known fields.
// It returns nil only when the whole document was consumed and every field
// assignment succeeded; every other outcome returns a non-nil error
// (typically errClaimsJSONFallback) telling the caller to fall back.
func (c *Claims) unmarshalFast(data []byte) error {
	if c == nil {
		// A typed-nil *Claims boxes as a non-nil FastUnmarshaler interface, so
		// DecodeSegment reaches this method instead of declining the
		// assertion. Decline here: the fallback's json.Unmarshal then produces
		// its canonical InvalidUnmarshalError rather than a nil-deref panic.
		return errClaimsJSONFallback
	}

	i := skipJSONSpace(data, 0)
	if i >= len(data) || data[i] != '{' {
		return errClaimsJSONFallback
	}
	i = skipJSONSpace(data, i+1)
	if i < len(data) && data[i] == '}' {
		return jsonTailIsSpace(data, i+1)
	}

	// slab packs the decoded scalar string fields into one shared allocation
	// (see slabString). Initialized lazily inside slabString, so payloads with
	// no string fields allocate nothing.
	var slab []byte

	for {
		if i >= len(data) || data[i] != '"' {
			return errClaimsJSONFallback
		}
		keyStart := i + 1
		keyEnd, err := scanJSONString(data, i)
		if err != nil {
			return errClaimsJSONFallback
		}
		key := data[keyStart : keyEnd-1]

		// Key preprocessing. encoding/json matches object keys to field names
		// exactly first, then case-insensitively (bytes.EqualFold). Known
		// Claims keys are all lowercase ASCII, so ASCII-folding the key
		// reproduces both forms. Keys with escapes or non-ASCII bytes are
		// declined: encoding/json unescapes keys (an escaped key can shorten
		// into a matching field name) and its EqualFold has non-ASCII corner
		// cases (e.g. 'ſ' folding to 's') this scanner does not reproduce.
		// Clean-ASCII keys longer than the longest field key cannot name a
		// field and are scanned but not dispatched.
		var folded [claimKeyBufSize]byte
		matchKey := len(key) <= claimKeyBufSize
		for j, b := range key {
			if b == '\\' || b >= 0x80 {
				return errClaimsJSONFallback
			}
			if matchKey {
				if b >= 'A' && b <= 'Z' {
					b += 32
				}
				folded[j] = b
			}
		}

		i = skipJSONSpace(data, keyEnd)
		if i >= len(data) || data[i] != ':' {
			return errClaimsJSONFallback
		}
		i = skipJSONSpace(data, i+1)
		if i >= len(data) {
			return errClaimsJSONFallback
		}
		valStart := i
		valEnd, err := scanJSONValue(data, i, 0)
		if err != nil {
			return errClaimsJSONFallback
		}
		if matchKey {
			if err := c.setClaimField(folded[:len(key)], data[valStart:valEnd], &slab); err != nil {
				return errClaimsJSONFallback
			}
		}

		i = skipJSONSpace(data, valEnd)
		if i >= len(data) {
			return errClaimsJSONFallback
		}
		switch data[i] {
		case ',':
			i = skipJSONSpace(data, i+1)
		case '}':
			return jsonTailIsSpace(data, i+1)
		default:
			return errClaimsJSONFallback
		}
	}
}

// jsonTailIsSpace reports whether data[i:] is all JSON whitespace, i.e. the
// document has no trailing content. The error result keeps call sites
// branch-free; the sentinel means "trailing garbage — fall back".
func jsonTailIsSpace(data []byte, i int) error {
	if skipJSONSpace(data, i) == len(data) {
		return nil
	}
	return errClaimsJSONFallback
}

// setClaimField assigns one decoded field. v is the raw JSON bytes of the
// value (numbers unquoted, strings with their quotes); slab receives the
// copies of accepted string values (see slabString). Unknown keys are
// ignored, matching encoding/json's default (no DisallowUnknownFields).
// Every non-nil error means "fall back" — including value-level errors like
// a malformed exp, which the fallback then re-derives with encoding/json's
// exact error value.
func (c *Claims) setClaimField(key, v []byte, slab *[]byte) error {
	switch string(key) {
	case "user_id":
		return setJSONString(&c.UserID, v, slab)
	case "username":
		return setJSONString(&c.Username, v, slab)
	case "role":
		return setJSONString(&c.Role, v, slab)
	case "session_id":
		return setJSONString(&c.SessionID, v, slab)
	case "client_id":
		return setJSONString(&c.ClientID, v, slab)
	case "iss":
		return setJSONString(&c.Issuer, v, slab)
	case "sub":
		return setJSONString(&c.Subject, v, slab)
	case "jti":
		return setJSONString(&c.ID, v, slab)
	case "token_type":
		// token_type only ever carries the two library constants; matching
		// them directly returns the canonical string without a copy. Any
		// other value (including escaped forms) takes the generic path.
		if string(v) == `"access"` {
			c.TokenType = TokenTypeAccess
			return nil
		}
		if string(v) == `"refresh"` {
			c.TokenType = TokenTypeRefresh
			return nil
		}
		return setJSONString(&c.TokenType, v, slab)
	case "aud":
		// StringOrSlice.UnmarshalJSON accepts the raw bytes, exactly what
		// encoding/json would hand it.
		return (&c.Audience).UnmarshalJSON(v)
	case "exp":
		return (&c.ExpiresAt).UnmarshalJSON(v)
	case "nbf":
		return (&c.NotBefore).UnmarshalJSON(v)
	case "iat":
		return (&c.IssuedAt).UnmarshalJSON(v)
	case "permissions":
		items, ok := fastStringArray(v)
		if !ok {
			return errClaimsJSONFallback
		}
		c.Permissions = items
		return nil
	case "scopes":
		items, ok := fastStringArray(v)
		if !ok {
			return errClaimsJSONFallback
		}
		c.Scopes = items
		return nil
	case "extra":
		return setExtraMap(&c.Extra, v)
	}
	return nil
}

// slabInitialCap is the capacity slabString grants a lazily created slab.
// It covers the scalar string content of a typical token (five short fields
// plus the 36-byte jti ≈ 68 bytes) so the common case never regrows.
const slabInitialCap = 96

// slabString appends b to *slab and returns an immutable string view of the
// copied bytes. Packing every decoded string of a structure into one slab
// replaces one allocation per string with one (occasionally two, on regrowth)
// per structure. Growth may move the slab's backing array, but append never
// mutates a region after it has been published, so earlier views stay valid
// and are kept alive by the strings that reference them. The slab is created
// lazily so structures that turn out to hold no strings allocate nothing.
func slabString(slab *[]byte, b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if *slab == nil {
		*slab = make([]byte, 0, max(slabInitialCap, len(b)))
	}
	off := len(*slab)
	*slab = append(*slab, b...)
	return unsafe.String(&(*slab)[off], len(b))
}

// setJSONString assigns a JSON string value to *dst. Strings containing
// escapes or non-ASCII bytes are declined: unquoting them exactly is
// encoding/json's job (invalid UTF-8, for instance, must produce its
// "invalid character" error, not a silently mangled Go string). null is a
// no-op, matching encoding/json for string destinations. Any other value
// type is declined so the fallback produces the canonical type error.
func setJSONString(dst *string, v []byte, slab *[]byte) error {
	if len(v) == 0 {
		return errClaimsJSONFallback
	}
	if v[0] == '"' {
		// scanJSONString already validated the structure; re-check the
		// content cheaply for the forms delegated to encoding/json.
		inner := v[1 : len(v)-1]
		for _, b := range inner {
			if b == '\\' || b >= 0x80 {
				return errClaimsJSONFallback
			}
		}
		*dst = slabString(slab, inner)
		return nil
	}
	if string(v) == "null" {
		return nil
	}
	return errClaimsJSONFallback
}

// fastStringArray decodes a JSON array of plain unescaped-ASCII strings and
// reports ok=true only when every element has that shape. Any other input —
// null, non-arrays, escaped or non-ASCII elements, malformed structure —
// yields ok=false so the caller declines to the fallback, where
// encoding/json owns the authoritative result (type errors included).
//
// Element bytes are packed into one slab (see slabString) instead of one
// allocation per element.
func fastStringArray(v []byte) ([]string, bool) {
	if len(v) == 0 || v[0] != '[' {
		return nil, false
	}
	// Pre-size from the quote count: every element this path accepts is an
	// unescaped string with exactly two quotes, so quotes/2 is exact for
	// accepted input. Escaped quotes inflate the estimate, but such arrays
	// are declined below regardless.
	quotes := bytes.Count(v, []byte{'"'})
	items := make([]string, 0, quotes/2)
	// Every accepted element is a string, so the slab is always used. Element
	// content (minus quotes, commas, whitespace) is strictly less than len(v),
	// so a full-length cap never regrows.
	slab := make([]byte, 0, len(v))
	i := skipJSONSpace(v, 1)
	if i < len(v) && v[i] == ']' {
		return items, true // empty array, non-nil like encoding/json's
	}
	for {
		if i >= len(v) || v[i] != '"' {
			return nil, false
		}
		end, err := scanJSONString(v, i)
		if err != nil {
			return nil, false
		}
		inner := v[i+1 : end-1]
		for k := range inner {
			if inner[k] == '\\' || inner[k] >= 0x80 {
				return nil, false
			}
		}
		items = append(items, slabString(&slab, inner))
		i = skipJSONSpace(v, end)
		if i >= len(v) {
			return nil, false
		}
		switch v[i] {
		case ',':
			i = skipJSONSpace(v, i+1)
		case ']':
			return items, true
		default:
			return nil, false
		}
	}
}

// setExtraMap decodes a flat JSON object into *dst, mirroring what
// encoding/json produces when decoding into map[string]any: strings, arrays
// of strings, float64 numbers, bools, and null. It decodes into an existing
// non-nil map (duplicate "extra" keys merge, matching encoding/json). Any
// other value shape — nested objects, mixed arrays, escaped strings or keys,
// non-ASCII — is declined to the payload-wide fallback.
//
// Keys and plain-string values are copied into one slab (see slabString)
// instead of one allocation per string.
func setExtraMap(dst *map[string]any, v []byte) error {
	if len(v) == 0 || v[0] != '{' {
		return errClaimsJSONFallback // null (non-object): encoding/json's call
	}
	m := *dst
	if m == nil {
		m = make(map[string]any, 8)
	}
	// Every entry carries a string key, so the slab is always used. Keys plus
	// string values are strictly less than len(v) (quotes/colons/commas are
	// not copied), so a full-length cap never regrows.
	slab := make([]byte, 0, len(v))
	i := skipJSONSpace(v, 1)
	if i < len(v) && v[i] == '}' {
		*dst = m // empty object keeps dst non-nil, like encoding/json
		return nil
	}
	for {
		if i >= len(v) || v[i] != '"' {
			return errClaimsJSONFallback
		}
		keyEnd, err := scanJSONString(v, i)
		if err != nil {
			return errClaimsJSONFallback
		}
		key := v[i+1 : keyEnd-1]
		for k := range key {
			if key[k] == '\\' || key[k] >= 0x80 {
				return errClaimsJSONFallback
			}
		}
		i = skipJSONSpace(v, keyEnd)
		if i >= len(v) || v[i] != ':' {
			return errClaimsJSONFallback
		}
		i = skipJSONSpace(v, i+1)
		if i >= len(v) {
			return errClaimsJSONFallback
		}

		var val any
		switch c := v[i]; {
		case c == '"':
			end, serr := scanJSONString(v, i)
			if serr != nil {
				return errClaimsJSONFallback
			}
			inner := v[i+1 : end-1]
			for k := range inner {
				if inner[k] == '\\' || inner[k] >= 0x80 {
					return errClaimsJSONFallback
				}
			}
			val = slabString(&slab, inner)
			i = end
		case c == '[':
			end, serr := scanJSONValue(v, i, 0)
			if serr != nil {
				return errClaimsJSONFallback
			}
			items, ok := fastStringArray(v[i:end])
			if !ok {
				return errClaimsJSONFallback
			}
			// encoding/json decodes arrays into any as []any; build that
			// type so decoded Extra values are indistinguishable from the
			// standard library's (reflect.DeepEqual included).
			vals := make([]any, len(items))
			for k, s := range items {
				vals[k] = s
			}
			val = vals
			i = end
		case c == 't' || c == 'f' || c == 'n':
			end, lit, lerr := scanJSONBoolOrNull(v, i)
			if lerr != nil {
				return errClaimsJSONFallback
			}
			val = lit
			i = end
		case c == '-' || (c >= '0' && c <= '9'):
			end, nerr := scanJSONNumber(v, i)
			if nerr != nil {
				return errClaimsJSONFallback
			}
			// encoding/json's interface decoding parses numbers with
			// strconv.ParseFloat; a parse error (e.g. out-of-range) is
			// delegated by declining here.
			f, perr := strconv.ParseFloat(string(v[i:end]), 64)
			if perr != nil {
				return errClaimsJSONFallback
			}
			val = f
			i = end
		default:
			return errClaimsJSONFallback
		}

		m[slabString(&slab, key)] = val
		i = skipJSONSpace(v, i)
		if i >= len(v) {
			return errClaimsJSONFallback
		}
		switch v[i] {
		case ',':
			i = skipJSONSpace(v, i+1)
		case '}':
			*dst = m
			return nil
		default:
			return errClaimsJSONFallback
		}
	}
}

// scanJSONBoolOrNull scans true/false/null at i and returns the index past
// the literal plus its Go value (bool or nil).
func scanJSONBoolOrNull(v []byte, i int) (int, any, error) {
	switch v[i] {
	case 't':
		if end, err := scanJSONLiteral(v, i, "true"); err == nil {
			return end, true, nil
		}
	case 'f':
		if end, err := scanJSONLiteral(v, i, "false"); err == nil {
			return end, false, nil
		}
	case 'n':
		if end, err := scanJSONLiteral(v, i, "null"); err == nil {
			return end, nil, nil
		}
	}
	return 0, nil, errClaimsJSONFallback
}

// skipJSONSpace advances past JSON whitespace (space, tab, newline, CR).
func skipJSONSpace(data []byte, i int) int {
	for i < len(data) {
		switch data[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return i
		}
	}
	return i
}

// scanJSONString returns the index just past the string starting at the
// opening quote data[i] == '"'. It validates escapes and rejects raw control
// bytes — both are errors under encoding/json — but performs no unquoting.
func scanJSONString(data []byte, i int) (int, error) {
	i++ // opening quote
	for i < len(data) {
		switch c := data[i]; {
		case c == '"':
			return i + 1, nil
		case c == '\\':
			i++
			if i >= len(data) {
				return 0, errClaimsJSONFallback // dangling backslash
			}
			switch data[i] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				i++
			case 'u':
				i++
				for range 4 {
					if i >= len(data) || !isJSONHex(data[i]) {
						return 0, errClaimsJSONFallback
					}
					i++
				}
			default:
				return 0, errClaimsJSONFallback // invalid escape
			}
		case c < 0x20:
			return 0, errClaimsJSONFallback // raw control byte
		default:
			i++
		}
	}
	return 0, errClaimsJSONFallback // unterminated string
}

func isJSONHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// scanJSONValue returns the index just past the JSON value starting at i,
// validating structure as it goes. Arrays and objects are recursed into with
// the same strict grammar; any byte sequence that is not unambiguously valid
// JSON yields errClaimsJSONFallback so the fallback decode produces the
// authoritative result (usually an error).
func scanJSONValue(data []byte, i, depth int) (int, error) {
	if depth > maxJSONDepth {
		return 0, errClaimsJSONFallback
	}
	switch c := data[i]; {
	case c == '"':
		return scanJSONString(data, i)
	case c == '{':
		i = skipJSONSpace(data, i+1)
		if i >= len(data) {
			return 0, errClaimsJSONFallback
		}
		if data[i] == '}' {
			return i + 1, nil
		}
		for {
			if data[i] != '"' {
				return 0, errClaimsJSONFallback
			}
			var err error
			i, err = scanJSONString(data, i)
			if err != nil {
				return 0, err
			}
			i = skipJSONSpace(data, i)
			if i >= len(data) || data[i] != ':' {
				return 0, errClaimsJSONFallback
			}
			i = skipJSONSpace(data, i+1)
			if i >= len(data) {
				return 0, errClaimsJSONFallback
			}
			i, err = scanJSONValue(data, i, depth+1)
			if err != nil {
				return 0, err
			}
			i = skipJSONSpace(data, i)
			if i >= len(data) {
				return 0, errClaimsJSONFallback
			}
			if data[i] == ',' {
				i = skipJSONSpace(data, i+1)
				if i >= len(data) {
					return 0, errClaimsJSONFallback
				}
				continue
			}
			if data[i] == '}' {
				return i + 1, nil
			}
			return 0, errClaimsJSONFallback
		}
	case c == '[':
		i = skipJSONSpace(data, i+1)
		if i >= len(data) {
			return 0, errClaimsJSONFallback
		}
		if data[i] == ']' {
			return i + 1, nil
		}
		for {
			var err error
			i, err = scanJSONValue(data, i, depth+1)
			if err != nil {
				return 0, err
			}
			i = skipJSONSpace(data, i)
			if i >= len(data) {
				return 0, errClaimsJSONFallback
			}
			if data[i] == ',' {
				i = skipJSONSpace(data, i+1)
				if i >= len(data) {
					return 0, errClaimsJSONFallback
				}
				continue
			}
			if data[i] == ']' {
				return i + 1, nil
			}
			return 0, errClaimsJSONFallback
		}
	case c == 't':
		return scanJSONLiteral(data, i, "true")
	case c == 'f':
		return scanJSONLiteral(data, i, "false")
	case c == 'n':
		return scanJSONLiteral(data, i, "null")
	case c == '-' || (c >= '0' && c <= '9'):
		return scanJSONNumber(data, i)
	}
	return 0, errClaimsJSONFallback
}

// scanJSONLiteral matches lit at i and returns the index just past it. A
// mismatch (e.g. "tru") is a fallback, not an error: encoding/json produces
// the definitive syntax error.
func scanJSONLiteral(data []byte, i int, lit string) (int, error) {
	end := i + len(lit)
	if end <= len(data) && string(data[i:end]) == lit {
		return end, nil
	}
	return 0, errClaimsJSONFallback
}

// scanJSONNumber returns the index just past the JSON number starting at i,
// enforcing the RFC 8259 grammar (no leading zeros, digits required after
// '.' and the exponent sign). Invalid forms fall back so encoding/json can
// report them; accepting one here would silently diverge from its behavior.
func scanJSONNumber(data []byte, i int) (int, error) {
	if data[i] == '-' {
		i++
	}
	// Integer part: a lone zero or a nonzero-leading digit sequence.
	switch {
	case i >= len(data):
		return 0, errClaimsJSONFallback
	case data[i] == '0':
		i++
	case data[i] >= '1' && data[i] <= '9':
		for i < len(data) && data[i] >= '0' && data[i] <= '9' {
			i++
		}
	default:
		return 0, errClaimsJSONFallback
	}
	// Fraction.
	if i < len(data) && data[i] == '.' {
		i++
		if i >= len(data) || data[i] < '0' || data[i] > '9' {
			return 0, errClaimsJSONFallback
		}
		for i < len(data) && data[i] >= '0' && data[i] <= '9' {
			i++
		}
	}
	// Exponent.
	if i < len(data) && (data[i] == 'e' || data[i] == 'E') {
		i++
		if i < len(data) && (data[i] == '+' || data[i] == '-') {
			i++
		}
		if i >= len(data) || data[i] < '0' || data[i] > '9' {
			return 0, errClaimsJSONFallback
		}
		for i < len(data) && data[i] >= '0' && data[i] <= '9' {
			i++
		}
	}
	return i, nil
}
