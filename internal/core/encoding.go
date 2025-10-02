package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func DecodeSegment(segment string, dest any) error {
	if len(segment) == 0 {
		return fmt.Errorf("empty segment")
	}

	const maxSegmentLength = 4096
	if len(segment) > maxSegmentLength {
		return fmt.Errorf("segment too large: maximum %d characters allowed for security", maxSegmentLength)
	}

	if !isValidBase64URL(segment) {
		return fmt.Errorf("invalid base64url characters in segment: potential injection attempt")
	}

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

func containsSuspiciousPatterns(s string) bool {
	for _, char := range s {
		if char < 32 && char != 9 && char != 10 && char != 13 {
			return true
		}
		if char == 0 {
			return true
		}
	}

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
