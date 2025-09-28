package jwt

import (
	"slices"
	"sync"
	"time"
)

// SigningMethod represents supported JWT signing algorithms
type SigningMethod string

const (
	SigningMethodHS256 SigningMethod = "HS256"
	SigningMethodHS384 SigningMethod = "HS384"
	SigningMethodHS512 SigningMethod = "HS512"
)

// RegisteredClaims represents the registered JWT claims
type RegisteredClaims struct {
	Issuer    string      `json:"iss,omitempty"`
	Subject   string      `json:"sub,omitempty"`
	Audience  []string    `json:"aud,omitempty"`
	ExpiresAt NumericDate `json:"exp,omitempty"`
	NotBefore NumericDate `json:"nbf,omitempty"`
	IssuedAt  NumericDate `json:"iat,omitempty"`
	ID        string      `json:"jti,omitempty"`
}

func (c *RegisteredClaims) reset() {
	c.Issuer = ""
	c.Subject = ""
	c.Audience = slices.Clip(c.Audience[:0])
	c.ExpiresAt = NumericDate{}
	c.NotBefore = NumericDate{}
	c.IssuedAt = NumericDate{}
	c.ID = ""
}

// Claims represents JWT claims with custom fields
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

	if c.Permissions != nil {
		c.Permissions = slices.Clip(c.Permissions[:0])
	}
	if c.Scopes != nil {
		c.Scopes = slices.Clip(c.Scopes[:0])
	}

	if c.Extra != nil {
		clear(c.Extra)
	}

	c.RegisteredClaims.reset()
}

type tokenInfo struct {
	claims    *Claims
	valid     bool
	expiresAt time.Time
	issuedAt  time.Time
	notBefore time.Time
	tokenID   string
	algorithm string
}

func (ti *tokenInfo) reset() {
	ti.claims = nil
	ti.valid = false
	ti.expiresAt = time.Time{}
	ti.issuedAt = time.Time{}
	ti.notBefore = time.Time{}
	ti.tokenID = ""
	ti.algorithm = ""
}

func (ti *tokenInfo) cleanup() {
	if ti.claims != nil {
		putClaims(ti.claims)
		ti.claims = nil
	}
	ti.reset()
	putTokenInfo(ti)
}

var (
	claimsPool = sync.Pool{
		New: func() any {
			return &Claims{
				Permissions: make([]string, 0, 8),
				Scopes:      make([]string, 0, 8),
				Extra:       make(map[string]any, 8),
				RegisteredClaims: RegisteredClaims{
					Audience: make([]string, 0, 2),
				},
			}
		},
	}

	tokenInfoPool = sync.Pool{
		New: func() any {
			return &tokenInfo{}
		},
	}
)

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

func getTokenInfo() *tokenInfo {
	ti := tokenInfoPool.Get().(*tokenInfo)
	ti.reset()
	return ti
}

func putTokenInfo(ti *tokenInfo) {
	if ti != nil {
		ti.reset()
		tokenInfoPool.Put(ti)
	}
}
