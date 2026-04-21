package jwt

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"
	"unsafe"
)

// maxValidTimestamp is the maximum valid Unix timestamp (9999-12-31 23:59:59 UTC).
// Timestamps beyond this value are considered invalid.
const maxValidTimestamp = 253402300799

// nullBytes is a pre-allocated byte slice for "null" JSON value.
var nullBytes = []byte("null")

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
// Returns the Unix timestamp as a JSON number, or "null" for zero time.
func (date *NumericDate) MarshalJSON() ([]byte, error) {
	if date.Time.IsZero() {
		return nullBytes, nil
	}

	unix := date.Unix()
	if unix < 0 || unix > maxValidTimestamp {
		return nullBytes, nil
	}

	// Use stack-allocated buffer for formatting (max 20 digits for int64)
	var buf [20]byte
	return strconv.AppendInt(buf[:0], unix, 10), nil
}

// UnmarshalJSON implements json.Unmarshaler for NumericDate.
// Parses a JSON number or string as a Unix timestamp.
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

	// SAFETY: b is a subslice of json.Decoder's internal buffer which is
	// alive for the duration of this UnmarshalJSON call. The resulting
	// string s does not escape this function, so the reference is safe.
	s := unsafe.String(unsafe.SliceData(b), len(b))
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}

	if s == "" || s == "null" {
		date.Time = time.Time{}
		return nil
	}

	// Use strconv.ParseInt for strict parsing (rejects inputs like "123abc")
	unix, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid time format: expected unix timestamp, got %s", s)
	}

	if unix < 0 || unix > maxValidTimestamp {
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
	SigningMethodPS256 SigningMethod = "PS256"
	SigningMethodPS384 SigningMethod = "PS384"
	SigningMethodPS512 SigningMethod = "PS512"

	// ECDSA signing methods (asymmetric)
	SigningMethodES256 SigningMethod = "ES256"
	SigningMethodES384 SigningMethod = "ES384"
	SigningMethodES512 SigningMethod = "ES512"
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

type RegisteredClaims struct {
	Issuer    string      `json:"iss,omitempty"`
	Subject   string      `json:"sub,omitempty"`
	Audience  StringOrSlice `json:"aud,omitempty"`
	ExpiresAt NumericDate `json:"exp"`
	NotBefore NumericDate `json:"nbf"`
	IssuedAt  NumericDate `json:"iat"`
	ID        string      `json:"jti,omitempty"`
}

// StringOrSlice holds a []string that can be unmarshaled from either
// a JSON string or a JSON array of strings, per RFC 7519 §4.1.3.
type StringOrSlice []string

// UnmarshalJSON implements json.Unmarshaler for StringOrSlice.
func (s *StringOrSlice) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		*s = nil
		return nil
	}
	if b[0] == '"' {
		var single string
		if err := json.Unmarshal(b, &single); err != nil {
			return err
		}
		*s = []string{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(b, &multi); err != nil {
		return err
	}
	*s = multi
	return nil
}

func (c *RegisteredClaims) reset() {
	c.Issuer = ""
	c.Subject = ""
	c.Audience = nil
	c.ExpiresAt = NumericDate{}
	c.NotBefore = NumericDate{}
	c.IssuedAt = NumericDate{}
	c.ID = ""
}

// Claims represents JWT claims with custom application-specific fields.
type Claims struct {
	UserID      string         `json:"user_id,omitempty"`
	Username    string         `json:"username,omitempty"`
	Role        string         `json:"role,omitempty"`
	Permissions []string       `json:"permissions,omitempty"`
	Scopes      []string       `json:"scopes,omitempty"`
	Extra       map[string]any `json:"extra,omitempty"`
	SessionID   string         `json:"session_id,omitempty"`
	ClientID    string         `json:"client_id,omitempty"`
	RegisteredClaims
}

func (c *Claims) reset() {
	c.UserID = ""
	c.Username = ""
	c.Role = ""
	c.SessionID = ""
	c.ClientID = ""

	// Set to nil instead of reallocating: copyClaims uses [:0:0] which
	// forces independent backing arrays, and JSON unmarshal creates new
	// allocations regardless. Avoids ~4 allocations per reset call.
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
	c := claimsPool.Get().(*Claims)
	c.reset()
	return c
}

func putClaims(c *Claims) {
	c.reset()
	claimsPool.Put(c)
}
