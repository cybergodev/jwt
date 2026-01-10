package jwt

import (
	"sync"
)

type SigningMethod string

const (
	SigningMethodHS256 SigningMethod = "HS256"
	SigningMethodHS384 SigningMethod = "HS384"
	SigningMethodHS512 SigningMethod = "HS512"
)

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
	c.Audience = c.Audience[:0]
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
	c.reset()
	claimsPool.Put(c)
}
