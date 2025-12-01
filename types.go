package jwt

import (
	"sync"
)

// SigningMethod represents supported JWT signing algorithms.
// All methods use HMAC with SHA-2 family hash functions.
type SigningMethod string

const (
	// SigningMethodHS256 uses HMAC with SHA-256 (recommended for most use cases)
	SigningMethodHS256 SigningMethod = "HS256"

	// SigningMethodHS384 uses HMAC with SHA-384 (higher security, larger signatures)
	SigningMethodHS384 SigningMethod = "HS384"

	// SigningMethodHS512 uses HMAC with SHA-512 (maximum security, largest signatures)
	SigningMethodHS512 SigningMethod = "HS512"
)

// RegisteredClaims represents the registered JWT claims as defined in RFC 7519.
// These are standard claims that have specific meanings in JWT tokens.
type RegisteredClaims struct {
	Issuer    string      `json:"iss,omitempty"` // Token issuer
	Subject   string      `json:"sub,omitempty"` // Token subject
	Audience  []string    `json:"aud,omitempty"` // Token audience
	ExpiresAt NumericDate `json:"exp"`           // Expiration time
	NotBefore NumericDate `json:"nbf"`           // Not valid before time
	IssuedAt  NumericDate `json:"iat"`           // Issued at time
	ID        string      `json:"jti,omitempty"` // Unique token identifier
}

func (c *RegisteredClaims) reset() {
	c.Issuer = ""
	c.Subject = ""
	c.Audience = c.Audience[:0]
	c.ExpiresAt = NumericDate{}
	c.NotBefore = NumericDate{}
	c.IssuedAt = NumericDate{}
	c.ID = ""
}

// Claims represents JWT claims with custom fields for application-specific data.
// It embeds RegisteredClaims and adds common authentication and authorization fields.
type Claims struct {
	UserID      string         `json:"user_id,omitempty"`     // Unique user identifier
	Username    string         `json:"username,omitempty"`    // Human-readable username
	Role        string         `json:"role,omitempty"`        // User role (e.g., "admin", "user")
	Permissions []string       `json:"permissions,omitempty"` // List of permissions
	Scopes      []string       `json:"scopes,omitempty"`      // OAuth2-style scopes
	Extra       map[string]any `json:"extra,omitempty"`       // Additional custom claims
	SessionID   string         `json:"session_id,omitempty"`  // Session identifier
	ClientID    string         `json:"client_id,omitempty"`   // Client application identifier
	RegisteredClaims
}

func (c *Claims) reset() {
	c.UserID = ""
	c.Username = ""
	c.Role = ""
	c.SessionID = ""
	c.ClientID = ""

	c.Permissions = c.Permissions[:0]
	c.Scopes = c.Scopes[:0]

	if c.Extra != nil {
		clear(c.Extra)
	}

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
	if c != nil {
		c.reset()
		claimsPool.Put(c)
	}
}
