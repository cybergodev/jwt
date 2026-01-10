package jwt

import (
	"fmt"
	"strings"
)

const (
	maxStringLength = 256
	maxArraySize    = 100
	maxExtraSize    = 50
)

func validateClaims(claims *Claims) error {
	if claims.UserID == "" && claims.Username == "" {
		return ErrInvalidClaims
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

	for i := 0; i < valueLen; i++ {
		c := value[i]
		if c < 32 && c != '\t' && c != '\n' && c != '\r' {
			return &ValidationError{
				Field:   fieldName,
				Message: "invalid control character",
			}
		}
	}

	if valueLen >= 4 && containsDangerousPattern(value) {
		return &ValidationError{
			Field:   fieldName,
			Message: "suspicious pattern detected",
		}
	}

	return nil
}

var dangerousPatterns = [...]string{
	"<script", "javascript:", "data:", "eval(", "../", "file://", "vbscript:",
	"alert(", "union select", "drop table", "exec(", "sp_", "/etc/passwd", "mocha:",
}

func containsDangerousPattern(value string) bool {
	if len(value) < 4 {
		return false
	}

	valueLower := strings.ToLower(value)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(valueLower, pattern) {
			return true
		}
	}
	return false
}
