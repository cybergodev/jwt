package jwt

import (
	"fmt"
	"math/bits"
)

const (
	maxStringLength = 256
	maxArraySize    = 100
	maxExtraSize    = 50
)

func validateClaims(claims *Claims) error {
	if err := claims.Validate(); err != nil {
		return err
	}

	// Reuse registered claims string validation (Issuer, Subject, ID, TokenType, Audience)
	if err := validateRegisteredClaimsStrings(&claims.RegisteredClaims); err != nil {
		return err
	}

	if err := validateString("UserID", claims.UserID, maxStringLength); err != nil {
		return err
	}
	if err := validateString("Username", claims.Username, maxStringLength); err != nil {
		return err
	}
	if err := validateString("Role", claims.Role, maxStringLength); err != nil {
		return err
	}
	if err := validateString("SessionID", claims.SessionID, maxStringLength); err != nil {
		return err
	}
	if err := validateString("ClientID", claims.ClientID, maxStringLength); err != nil {
		return err
	}

	if err := validateStringArray("permissions", claims.Permissions); err != nil {
		return err
	}
	if err := validateStringArray("scopes", claims.Scopes); err != nil {
		return err
	}

	if len(claims.Extra) > maxExtraSize {
		return &ValidationError{
			Field:   "extra",
			Message: fmt.Sprintf("exceeds maximum of %d fields", maxExtraSize),
		}
	}

	for key, value := range claims.Extra {
		if err := validateString("extra."+key, key, maxStringLength); err != nil {
			return err
		}
		switch v := value.(type) {
		case string:
			if err := validateString("extra."+key, v, maxStringLength); err != nil {
				return err
			}
		case []string:
			for _, item := range v {
				if err := validateString("extra."+key, item, maxStringLength); err != nil {
					return err
				}
			}
		case map[string]any:
			return &ValidationError{
				Field:   "extra." + key,
				Message: "nested maps not allowed",
			}
		default:
			return &ValidationError{
				Field:   "extra." + key,
				Message: fmt.Sprintf("unsupported type %T", value),
			}
		}
	}

	return nil
}

func validateStringArray(name string, items []string) error {
	if len(items) > maxArraySize {
		return &ValidationError{
			Field:   name,
			Message: fmt.Sprintf("exceeds maximum of %d items", maxArraySize),
		}
	}
	for _, item := range items {
		if err := validateString(name, item, maxStringLength); err != nil {
			return err
		}
	}
	return nil
}

func validateString(fieldName, value string, maxLength int) error {
	valueLen := len(value)
	if valueLen == 0 {
		return nil
	}

	if valueLen > maxLength {
		return &ValidationError{
			Field:   fieldName,
			Message: fmt.Sprintf("exceeds maximum length of %d", maxLength),
		}
	}

	// Single pass: control char check + dangerous pattern detection.
	// For positions where the first-byte index has no matching patterns
	// (the common case for alphanumeric claims), the inner loop is skipped entirely.
	patternEnd := valueLen - 2 // shortest pattern is 3 chars
	for i := 0; i < valueLen; i++ {
		c := value[i]
		if isControlChar(c) {
			return &ValidationError{
				Field:   fieldName,
				Message: "invalid control character",
			}
		}
		if i < patternEnd {
			mask := patternMask[c]
			if mask != 0 && matchPatternsAt(value, i, mask) {
				return &ValidationError{
					Field:   fieldName,
					Message: "suspicious pattern detected",
				}
			}
		}
	}

	return nil
}

// isControlChar checks if a byte is an invalid control character.
// Valid control characters: tab (9), newline (10), carriage return (13).
func isControlChar(c byte) bool {
	return c < 32 && c != 9 && c != 10 && c != 13
}

// dangerousPatterns contains patterns that may indicate injection attacks.
// Patterns are chosen to minimize false positives on legitimate data.
var dangerousPatterns = []string{
	"../",
	"<svg", "<img", "<map",
	"<math", "<link", "<meta", "<form", "<base",
	"<body", "<html", "<embed", "<area", "mocha:", "ondrag", "ondrop",
	"<input", "<audio", "<style", "alert(",
	"onfocus", "onblur", "<video", "<track", "<iframe", "<object", "<portal", "<source",
	"onclick", "onerror", "onload", "<textarea",
	"onchange", "onsubmit", "onkeyup", "<!doctype", "file://",
	"onkeydown", "drop table",
	"onkeypress", "<script", "vbscript:",
	"onmouseover", "union select",
	"javascript:",
	"/etc/passwd",
}

// patternMask maps each byte value to a bitmask of dangerousPatterns indices
// whose first character matches (case-insensitive). This enables O(1) filtering:
// for each position in the input, only patterns whose first byte matches the
// current character are checked. For typical alphanumeric JWT claims, almost
// every position has zero candidate patterns, reducing work from O(n*39) to
// near O(n).
var patternMask [256]uint64

func init() {
	if len(dangerousPatterns) > 64 {
		panic("dangerousPatterns exceeds 64 entries; widen patternMask type")
	}
	for i, p := range dangerousPatterns {
		if len(p) == 0 {
			continue
		}
		c := p[0]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		patternMask[c] |= 1 << uint(i)
		if c >= 'a' && c <= 'z' {
			patternMask[c-32] |= 1 << uint(i)
		}
	}
}

// matchPatternsAt checks all dangerous patterns whose first byte matches
// value[pos], using the precomputed bitmask. Returns true if any pattern
// matches case-insensitively at the given position.
func matchPatternsAt(value string, pos int, mask uint64) bool {
	n := len(value)
	for mask != 0 {
		bit := bits.TrailingZeros64(mask)
		pattern := dangerousPatterns[bit]
		mask &= mask - 1 // clear lowest set bit
		pl := len(pattern)
		if pos+pl > n {
			continue
		}
		// First character already matched via patternMask; check remaining.
		match := true
		for j := 1; j < pl; j++ {
			sc := value[pos+j]
			pc := pattern[j]
			if sc != pc {
				if sc >= 'A' && sc <= 'Z' {
					sc += 32
				}
				if sc != pc {
					match = false
					break
				}
			}
		}
		if match {
			return true
		}
	}
	return false
}

// validateRegisteredClaimsStrings validates string fields in RegisteredClaims
// for length limits and injection patterns. Used for custom claims types
// that don't go through the deep validateClaims path.
func validateRegisteredClaimsStrings(rc *RegisteredClaims) error {
	if err := validateString("Issuer", rc.Issuer, maxStringLength); err != nil {
		return err
	}
	if err := validateString("Subject", rc.Subject, maxStringLength); err != nil {
		return err
	}
	if err := validateString("ID", rc.ID, maxStringLength); err != nil {
		return err
	}
	if err := validateString("TokenType", rc.TokenType, maxStringLength); err != nil {
		return err
	}
	return validateStringArray("audience", rc.Audience)
}
