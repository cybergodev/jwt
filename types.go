package jwt

import (
	"crypto"
	"fmt"
	"strconv"
	"sync"
	"time"
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
	if len(b) == 0 || string(b) == "null" {
		date.Time = time.Time{}
		return nil
	}

	s := string(b)
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

	// RSA signing methods (asymmetric)
	SigningMethodRS256 SigningMethod = "RS256"
	SigningMethodRS384 SigningMethod = "RS384"
	SigningMethodRS512 SigningMethod = "RS512"

	// ECDSA signing methods (asymmetric)
	SigningMethodES256 SigningMethod = "ES256"
	SigningMethodES384 SigningMethod = "ES384"
	SigningMethodES512 SigningMethod = "ES512"
)

// Signer defines the interface for custom signing algorithms.
// Implementations must be safe for concurrent use.
//
// Example implementation:
//
//	type CustomSigner struct {
//	    secretKey []byte
//	}
//
//	func (s *CustomSigner) Alg() string { return "CUSTOM" }
//	func (s *CustomSigner) Sign(data string) (string, error) { ... }
//	func (s *CustomSigner) Verify(data, signature string) error { ... }
type Signer interface {
	// Alg returns the algorithm identifier (e.g., "HS256", "RS256").
	Alg() string

	// Sign creates a signature for the given data.
	Sign(data string) (string, error)

	// Verify checks if the signature is valid for the given data.
	Verify(data, signature string) error

	// Hash returns the hash function used by this signer.
	Hash() crypto.Hash
}

type RegisteredClaims struct {
	Issuer    string      `json:"iss,omitempty"`
	Subject   string      `json:"sub,omitempty"`
	Audience  []string    `json:"aud,omitempty"`
	ExpiresAt NumericDate `json:"exp"`
	NotBefore NumericDate `json:"nbf"`
	IssuedAt  NumericDate `json:"iat"`
	ID        string      `json:"jti,omitempty"`
}

func (c *RegisteredClaims) reset() {
	c.Issuer = ""
	c.Subject = ""
	// Reallocate slice to avoid data races with sync.Pool
	c.Audience = make([]string, 0, cap(c.Audience))
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

	// Reallocate slices to avoid data races with sync.Pool
	// When an object is returned to the pool, another goroutine might
	// still be reading the old slice/map during JSON marshaling
	c.Permissions = make([]string, 0, cap(c.Permissions))
	c.Scopes = make([]string, 0, cap(c.Scopes))

	// Reallocate Extra map to avoid data races
	// clear() would modify the map that might be in use by another goroutine
	extraCap := 4
	if c.Extra != nil {
		extraCap = len(c.Extra)
		if extraCap < 4 {
			extraCap = 4
		}
	}
	c.Extra = make(map[string]any, extraCap)

	c.RegisteredClaims.reset()
}

var claimsPool = sync.Pool{
	New: func() any {
		return &Claims{
			Permissions: make([]string, 0, 8),
			Scopes:      make([]string, 0, 8),
			Extra:       make(map[string]any, 4),
			RegisteredClaims: RegisteredClaims{
				Audience: make([]string, 0, 2),
			},
		}
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
