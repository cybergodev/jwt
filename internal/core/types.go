package core

import (
	"github.com/cybergodev/jwt/internal/signing"
)

// Core represents a JWT token with header, payload, and signature
type Core struct {
	Header    map[string]any `json:"header"`
	Claims    any            `json:"claims"`
	Signature string         `json:"-"`
	Method    signing.Method
	Valid     bool
	Raw       string
}

const (
	// TokenIDLength defines the length of generated token IDs
	TokenIDLength = 16
)
