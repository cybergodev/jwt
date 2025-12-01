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
			Message: fmt.Sprintf("too many fields: maximum %d allowed", maxExtraSize),
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
			Message: fmt.Sprintf("too many items: maximum %d allowed", maxArraySize),
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
	if len(value) == 0 {
		return nil
	}

	if len(value) > maxLength {
		return &ValidationError{
			Field:   fieldName,
			Message: fmt.Sprintf("too long: maximum %d characters", maxLength),
		}
	}

	for i := 0; i < len(value); i++ {
		char := value[i]
		if char < 32 && char != '\t' && char != '\n' && char != '\r' {
			return &ValidationError{
				Field:   fieldName,
				Message: "contains invalid control character",
			}
		}
	}

	if containsDangerousPattern(value) {
		return &ValidationError{
			Field:   fieldName,
			Message: "contains suspicious pattern",
		}
	}

	return nil
}

var dangerousPatterns = [...]string{
	"<script", "javascript:", "data:", "eval(", "../", "file://", "vbscript:",
}

func containsDangerousPattern(value string) bool {
	valueLen := len(value)
	if valueLen < 4 {
		return false
	}

	for _, pattern := range dangerousPatterns {
		patternLen := len(pattern)
		if patternLen > valueLen {
			continue
		}

		for i := 0; i <= valueLen-patternLen; i++ {
			match := true
			for j := 0; j < patternLen; j++ {
				c := value[i+j]
				pc := pattern[j]
				if c >= 'A' && c <= 'Z' {
					c += 32
				}
				if c != pc {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}
