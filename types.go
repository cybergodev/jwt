package jwt

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// maxValidTimestamp is the maximum valid Unix timestamp (9999-12-31 23:59:59 UTC).
// Timestamps beyond this value are considered invalid.
const maxValidTimestamp = 253402300799

// NumericDate represents a JSON numeric date value (Unix timestamp).
// It is used for JWT timestamp claims (exp, nbf, iat).
type NumericDate struct {
	time.Time
}

// NewNumericDate creates a new NumericDate from a time.Time value.
func NewNumericDate(t time.Time) NumericDate {
	return NumericDate{Time: t}
}

// MarshalJSON implements json.Marshaler for NumericDate.
// Returns the Unix timestamp as a JSON number. Returns "null" for the zero
// time and for values outside [0, maxValidTimestamp] (pre-1970 dates and
// far-future timestamps); UnmarshalJSON rejects such values outright, so
// they cannot round-trip.
//
// The receiver is a value so that marshaling a Claims value (not a pointer)
// also emits Unix numbers: with a pointer receiver, encoding/json cannot
// find the method on non-addressable values and would fall back to
// time.Time's RFC3339 string format, breaking interoperability. The library
// itself always marshals claims through pointers, so its output is unchanged.
//
// The "null" results are freshly allocated per call: a shared pre-allocated
// slice handed to callers would let one mutation of the returned buffer
// corrupt every future "null" emitted package-wide. This method is off the
// library's hot paths (AppendJSON emits the literal directly), so the cost
// is confined to reflection-driven marshaling of user types.
func (date NumericDate) MarshalJSON() ([]byte, error) {
	if date.IsZero() {
		return []byte("null"), nil
	}

	unix := date.Unix()
	if unix < 0 || unix > maxValidTimestamp {
		return []byte("null"), nil
	}

	// Format into a 20-byte buffer (max int64 is 19 digits). AppendInt returns a
	// slice over buf; buf escapes to the heap as the return value, but this still
	// avoids the extra string→[]byte copy that strconv.FormatInt would require.
	var buf [20]byte
	return strconv.AppendInt(buf[:0], unix, 10), nil
}

// maxInt64Div10 and maxInt64Mod10 together form the standard int64 overflow
// guard for base-10 parsing. Used by parseDecimalInt64.
const (
	maxInt64Div10 = (1<<63 - 1) / 10
	maxInt64Mod10 = (1<<63 - 1) % 10 // == 7
)

// parseDecimalInt64 parses a non-negative base-10 integer from b without
// allocating a string. Returns the value and true on success, or 0 and false
// if b is empty or contains any byte outside '0'..'9' — which also rejects
// negative numbers, decimals, and trailing characters (matching strconv.ParseInt
// for these cases). Values that would overflow int64 are rejected; this MUST be
// detected here rather than by a post-parse range check, because a wrapped
// (negative) result would silently bypass such a check.
//
// It exists so NumericDate.UnmarshalJSON can avoid the string(b) allocation
// that strconv.ParseInt would require on the hot validation path (profiling
// showed NumericDate.UnmarshalJSON accounting for ~18% of validation allocations).
func parseDecimalInt64(b []byte) (int64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	var n int64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		digit := int64(c - '0')
		// Reject before the multiply would overflow int64. When n equals
		// maxInt64Div10 exactly, only digits <= maxInt64Mod10 (7) are safe.
		if n > maxInt64Div10 || (n == maxInt64Div10 && digit > maxInt64Mod10) {
			return 0, false
		}
		n = n*10 + digit
	}
	return n, true
}

// UnmarshalJSON implements json.Unmarshaler for NumericDate.
// Parses a JSON number or string as a Unix timestamp.
//
// The hot path (a valid numeric timestamp) is allocation-free: quote stripping
// and integer parsing both operate on the input bytes directly. The only string
// conversion happens in the error branch, which is cold.
func (date *NumericDate) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		date.Time = time.Time{}
		return nil
	}

	// Fast null check without allocation
	if len(b) == 4 && b[0] == 'n' && b[1] == 'u' && b[2] == 'l' && b[3] == 'l' {
		date.Time = time.Time{}
		return nil
	}

	// Strip surrounding quotes (some JWTs encode dates as JSON strings) by
	// reslicing the input bytes rather than converting to a string.
	d := b
	if len(d) >= 2 && d[0] == '"' && d[len(d)-1] == '"' {
		d = d[1 : len(d)-1]
	}

	if len(d) == 0 {
		date.Time = time.Time{}
		return nil
	}

	// Quoted "null" → zero.
	if len(d) == 4 && d[0] == 'n' && d[1] == 'u' && d[2] == 'l' && d[3] == 'l' {
		date.Time = time.Time{}
		return nil
	}

	unix, ok := parseDecimalInt64(d)
	if !ok {
		// Cold path: allocate only to report the offending value.
		return fmt.Errorf("invalid time format: expected unix timestamp, got %s", string(b))
	}

	// parseDecimalInt64 rejects negatives and decimals, so unix is >= 0 here.
	if unix > maxValidTimestamp {
		return fmt.Errorf("invalid unix timestamp: %d", unix)
	}

	date.Time = time.Unix(unix, 0).UTC()
	return nil
}

// SigningMethod defines the algorithm used to sign tokens.
type SigningMethod string

// Supported signing methods.
const (
	// HMAC signing methods (symmetric)
	SigningMethodHS256 SigningMethod = "HS256"
	SigningMethodHS384 SigningMethod = "HS384"
	SigningMethodHS512 SigningMethod = "HS512"

	// RSA signing methods (asymmetric, PKCS#1 v1.5)
	SigningMethodRS256 SigningMethod = "RS256"
	SigningMethodRS384 SigningMethod = "RS384"
	SigningMethodRS512 SigningMethod = "RS512"

	// RSA-PSS signing methods (asymmetric, recommended over PKCS#1 v1.5)
	// SigningMethodPS256 uses RSA-PSS with SHA-256.
	SigningMethodPS256 SigningMethod = "PS256"
	// SigningMethodPS384 uses RSA-PSS with SHA-384.
	SigningMethodPS384 SigningMethod = "PS384"
	// SigningMethodPS512 uses RSA-PSS with SHA-512.
	SigningMethodPS512 SigningMethod = "PS512"

	// ECDSA signing methods (asymmetric)
	SigningMethodES256 SigningMethod = "ES256"
	SigningMethodES384 SigningMethod = "ES384"
	SigningMethodES512 SigningMethod = "ES512"
)

// Token type constants used in the RegisteredClaims TokenType field.
// Access tokens are created by [Processor.Create]; refresh tokens by [Processor.CreateRefresh].
// The [Processor.Refresh] and [Processor.RefreshInto] methods reject tokens with TokenTypeAccess.
const (
	// TokenTypeAccess marks a token as an access token.
	TokenTypeAccess = "access"
	// TokenTypeRefresh marks a token as a refresh token.
	TokenTypeRefresh = "refresh"
)

// isHMAC returns true if the signing method uses HMAC (symmetric) algorithms.
func (m SigningMethod) isHMAC() bool {
	switch m {
	case SigningMethodHS256, SigningMethodHS384, SigningMethodHS512:
		return true
	}
	return false
}

// isAsymmetric returns true if the signing method uses asymmetric algorithms (RSA/ECDSA).
func (m SigningMethod) isAsymmetric() bool {
	switch m {
	case SigningMethodRS256, SigningMethodRS384, SigningMethodRS512,
		SigningMethodPS256, SigningMethodPS384, SigningMethodPS512,
		SigningMethodES256, SigningMethodES384, SigningMethodES512:
		return true
	}
	return false
}

// isValid returns true if the signing method is a recognized built-in algorithm.
func (m SigningMethod) isValid() bool {
	return m.isHMAC() || m.isAsymmetric()
}

// RegisteredClaims contains the standard JWT claims defined in RFC 7519 §4.1.
// These are set automatically during token creation and validated during verification.
type RegisteredClaims struct {
	// Issuer (iss) identifies the principal that issued the token.
	Issuer string `json:"iss,omitempty"`
	// Subject (sub) identifies the principal that is the subject of the token.
	Subject string `json:"sub,omitempty"`
	// Audience (aud) identifies the recipients the token is intended for.
	// Validated against Config.ExpectedAudience when that field is set.
	Audience StringOrSlice `json:"aud,omitempty"`
	// ExpiresAt (exp) is the time after which the token must no longer be accepted.
	ExpiresAt NumericDate `json:"exp"`
	// NotBefore (nbf) is the time before which the token must not be accepted.
	NotBefore NumericDate `json:"nbf"`
	// IssuedAt (iat) is the time at which the token was issued.
	IssuedAt NumericDate `json:"iat"`
	// ID (jti) is a unique identifier for the token; used as the blacklist key.
	ID string `json:"jti,omitempty"`
	// TokenType marks the token as "access" or "refresh" (see TokenTypeAccess).
	TokenType string `json:"token_type,omitempty"`
}

// StringOrSlice holds a []string that can be unmarshaled from either
// a JSON string or a JSON array of strings, per RFC 7519 §4.1.3.
type StringOrSlice []string

// UnmarshalJSON implements json.Unmarshaler for StringOrSlice.
// The common shapes — a plain unescaped-ASCII string, or an array of them —
// decode via the same strict scanner the Claims fast path uses (see
// claims_json.go), skipping encoding/json's machinery. Any other input
// (escapes, non-ASCII, other JSON types) falls back to encoding/json, which
// owns the authoritative result including error values.
func (s *StringOrSlice) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		*s = nil
		return nil
	}
	if b[0] == '"' {
		if end, err := scanJSONString(b, 0); err == nil && jsonTailIsSpace(b, end) == nil {
			inner := b[1 : end-1]
			plain := true
			for k := range inner {
				if inner[k] == '\\' || inner[k] >= 0x80 {
					plain = false
					break
				}
			}
			if plain {
				*s = []string{string(inner)}
				return nil
			}
		}
		var single string
		if err := json.Unmarshal(b, &single); err != nil {
			return err
		}
		*s = []string{single}
		return nil
	}
	if items, ok := fastStringArray(b); ok {
		*s = items
		return nil
	}
	var multi []string
	if err := json.Unmarshal(b, &multi); err != nil {
		return err
	}
	*s = multi
	return nil
}

// MarshalJSON implements json.Marshaler for StringOrSlice.
// A single-element slice is serialized as a JSON string per RFC 7519 §4.1.3.
func (s StringOrSlice) MarshalJSON() ([]byte, error) {
	if len(s) == 1 {
		return json.Marshal(s[0])
	}
	return json.Marshal([]string(s))
}

func (c *RegisteredClaims) reset() {
	c.Issuer = ""
	c.Subject = ""
	c.Audience = nil
	c.ExpiresAt = NumericDate{}
	c.NotBefore = NumericDate{}
	c.IssuedAt = NumericDate{}
	c.ID = ""
	c.TokenType = ""
}

// Claims represents JWT claims with custom application-specific fields.
type Claims struct {
	// UserID is the application-specific user identifier. Either UserID or
	// Username must be non-empty for a claim set to pass validation.
	UserID string `json:"user_id,omitempty"`
	// Username is a human-readable user name.
	Username string `json:"username,omitempty"`
	// Role is the user's role (e.g. "admin", "user").
	Role string `json:"role,omitempty"`
	// Permissions is a list of permission strings granted to the subject.
	Permissions []string `json:"permissions,omitempty"`
	// Scopes is a list of OAuth-style scope strings granted to the subject.
	Scopes []string `json:"scopes,omitempty"`
	// Extra holds arbitrary additional claim fields. Values may be string,
	// []string, or other JSON types; nested maps are rejected by validation.
	Extra map[string]any `json:"extra,omitempty"`
	// SessionID associates the token with a server-side session.
	SessionID string `json:"session_id,omitempty"`
	// ClientID identifies the client (e.g. OAuth client) the token was issued to.
	ClientID string `json:"client_id,omitempty"`
	// RegisteredClaims holds the standard JWT claims (iss, sub, exp, ...).
	RegisteredClaims
}

func (c *Claims) reset() {
	c.UserID = ""
	c.Username = ""
	c.Role = ""
	c.SessionID = ""
	c.ClientID = ""

	// Set to nil for GC: copyClaims deep-copies and JSON unmarshal allocates fresh.
	c.Permissions = nil
	c.Scopes = nil
	c.Extra = nil

	c.RegisteredClaims.reset()
}

var claimsPool = sync.Pool{
	New: func() any {
		return new(Claims)
	},
}

func getClaims() *Claims {
	// No reset here: putClaims zeroes every *Claims before pooling it, and the
	// pool's New returns a zero value, so a recycled object is already clean.
	// The second reset this function used to perform was pure dead work on
	// every parse (a full ~300-byte struct clear).
	return claimsPool.Get().(*Claims)
}

func putClaims(c *Claims) {
	c.reset()
	claimsPool.Put(c)
}
