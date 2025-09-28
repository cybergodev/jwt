package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// DecodeSegment decodes a base64url encoded JWT segment with security validations
func DecodeSegment(segment string, dest any) error {
	// Comprehensive input validation to prevent attacks
	if len(segment) == 0 {
		return fmt.Errorf("empty segment")
	}

	const maxSegmentLength = 4096
	if len(segment) > maxSegmentLength {
		return fmt.Errorf("segment too large: maximum %d characters allowed for security", maxSegmentLength)
	}

	// Strict base64url validation to prevent injection attacks
	if !isValidBase64URL(segment) {
		return fmt.Errorf("invalid base64url characters in segment: potential injection attempt")
	}

	// Check for suspicious patterns that might indicate attacks
	if containsSuspiciousPatterns(segment) {
		return fmt.Errorf("suspicious patterns detected in segment")
	}

	bufLen := base64.RawURLEncoding.DecodedLen(len(segment))

	const maxDecodedLength = 2048
	if bufLen > maxDecodedLength {
		return fmt.Errorf("decoded segment too large: maximum %d bytes allowed", maxDecodedLength)
	}

	buf := make([]byte, bufLen)

	n, err := base64.RawURLEncoding.Decode(buf, []byte(segment))
	if err != nil {
		return fmt.Errorf("failed to decode base64url: %w", err)
	}

	if err := json.Unmarshal(buf[:n], dest); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return nil
}

// isValidBase64URL checks if string contains only valid base64url characters
func isValidBase64URL(s string) bool {
	for _, char := range s {
		if !((char >= 'A' && char <= 'Z') ||
			(char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_') {
			return false
		}
	}
	return true
}

// containsSuspiciousPatterns detects suspicious patterns that might indicate attacks
func containsSuspiciousPatterns(s string) bool {
	// Check for excessively long repeated characters
	if len(s) > 100 {
		charCount := make(map[rune]int)
		for _, char := range s {
			charCount[char]++
			if charCount[char] > len(s)/2 {
				return true
			}
		}
	}

	// Check for null bytes or control characters
	for _, char := range s {
		if char < 32 && char != 9 && char != 10 && char != 13 {
			return true
		}
		if char == 0 {
			return true
		}
	}

	// Check for potential script injection patterns
	suspiciousPatterns := []string{
		"<script", "</script", "javascript:", "data:", "vbscript:",
		"onload=", "onerror=", "onclick=", "eval(", "alert(",
	}

	lowerS := strings.ToLower(s)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerS, pattern) {
			return true
		}
	}

	return false
}
