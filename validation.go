package jwt

import (
	"fmt"
)

const (
	maxStringLength = 256
	maxArraySize    = 100
	maxExtraSize    = 50
)

func validateClaims(claims *Claims) error {
	// Use Claims.Validate() for basic validation
	if err := claims.Validate(); err != nil {
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
	if err := validateString("Issuer", claims.Issuer, maxStringLength); err != nil {
		return err
	}
	if err := validateString("Subject", claims.Subject, maxStringLength); err != nil {
		return err
	}
	if err := validateString("ID", claims.ID, maxStringLength); err != nil {
		return err
	}

	if err := validateStringArray("permissions", claims.Permissions); err != nil {
		return err
	}
	if err := validateStringArray("scopes", claims.Scopes); err != nil {
		return err
	}
	if err := validateStringArray("audience", claims.Audience); err != nil {
		return err
	}

	if len(claims.Extra) > maxExtraSize {
		return &ValidationError{
			Field:   "extra",
			Message: fmt.Sprintf("exceeds maximum of %d fields", maxExtraSize),
		}
	}

	for key, value := range claims.Extra {
		if err := validateString("extra_key", key, maxStringLength); err != nil {
			return err
		}
		switch v := value.(type) {
		case string:
			if err := validateString("extra_value", v, maxStringLength); err != nil {
				return err
			}
		case []string:
			for _, item := range v {
				if err := validateString("extra_array_item", item, maxStringLength); err != nil {
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

	// Optimized control character check using bit operations
	// Check 8 bytes at a time for longer strings
	if valueLen >= 8 {
		for i := 0; i <= valueLen-8; i += 8 {
			b0, b1, b2, b3 := value[i], value[i+1], value[i+2], value[i+3]
			b4, b5, b6, b7 := value[i+4], value[i+5], value[i+6], value[i+7]
			if isControlChar(b0) || isControlChar(b1) || isControlChar(b2) || isControlChar(b3) ||
				isControlChar(b4) || isControlChar(b5) || isControlChar(b6) || isControlChar(b7) {
				return &ValidationError{
					Field:   fieldName,
					Message: "invalid control character",
				}
			}
		}
		// Check remaining bytes
		for i := (valueLen / 8) * 8; i < valueLen; i++ {
			if isControlChar(value[i]) {
				return &ValidationError{
					Field:   fieldName,
					Message: "invalid control character",
				}
			}
		}
	} else {
		for i := 0; i < valueLen; i++ {
			if isControlChar(value[i]) {
				return &ValidationError{
					Field:   fieldName,
					Message: "invalid control character",
				}
			}
		}
	}

	if valueLen >= 3 && containsDangerousPattern(value) {
		return &ValidationError{
			Field:   fieldName,
			Message: "suspicious pattern detected",
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
	"javascript:", "expression(",
	"/etc/passwd",
}

// containsDangerousPattern checks if value contains any dangerous pattern.
// Uses case-insensitive comparison without allocating a new string.
func containsDangerousPattern(value string) bool {
	if len(value) < 3 {
		return false
	}

	// Fast path: check for patterns using case-insensitive substring search
	// without allocating a new lowercase string
	for _, pattern := range dangerousPatterns {
		if len(value) < len(pattern) {
			continue
		}
		if hasSubstringIgnoreCase(value, pattern) {
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
	return validateStringArray("audience", rc.Audience)
}

// hasSubstringIgnoreCase performs case-insensitive substring search.
// This avoids allocating a new string like strings.ToLower would.
func hasSubstringIgnoreCase(s, substr string) bool {
	substrLen := len(substr)
	if substrLen == 0 {
		return true
	}
	if len(s) < substrLen {
		return false
	}

	firstChar := substr[0]
	firstLower := firstChar
	if firstChar >= 'A' && firstChar <= 'Z' {
		firstLower = firstChar + 32
	}

	end := len(s) - substrLen + 1
	for i := 0; i < end; i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		if c != firstLower {
			continue
		}

		// Check remaining characters
		match := true
		for j := 1; j < substrLen; j++ {
			sc := s[i+j]
			pc := substr[j]
			// Fast case-insensitive comparison for ASCII letters
			if sc != pc {
				if (sc >= 'A' && sc <= 'Z' && sc+32 != pc) ||
					(sc >= 'a' && sc <= 'z' && sc-32 != pc) ||
					(sc < 'A' || sc > 'z' || (sc > 'Z' && sc < 'a')) {
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
