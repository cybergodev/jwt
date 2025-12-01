package core

import (
	"github.com/cybergodev/jwt/internal/signing"
)

// Core represents a JWT token with header, payload, and signature.
// It is used internally for token parsing and validation.
type Core struct {
	Header    map[string]any `json:"header"` // JWT header containing algorithm and type
	Claims    any            `json:"claims"` // JWT claims (payload)
	Signature string         `json:"-"`      // Base64-encoded signature
	Method    signing.Method // Signing method used
	Valid     bool           // Whether signature is valid
	Raw       string         // Original token string
}

const (
	// TokenIDLength defines the length of generated token IDs in bytes
	TokenIDLength = 16
)
