package security

import (
	"runtime"
	"strings"
)

// ZeroBytes securely zeros out a byte slice to prevent sensitive data from remaining in memory.
// It performs multiple passes with different patterns to resist memory forensics.
// This function should be called on secret keys and sensitive data before they go out of scope.
func ZeroBytes(data []byte) {
	clear(data)
	for i := range data {
		data[i] = 0xFF
	}
	clear(data)
	runtime.KeepAlive(data)
}

var weakPatterns = [...]string{
	"password", "12345678", "qwerty", "admin", "test",
	"default", "example", "demo", "temp", "secret",
}

// IsWeakKey checks if a key is weak based on common patterns and entropy.
// It detects keys with low entropy, common patterns, sequential characters, and weak passwords.
// Returns true if the key is considered weak and should not be used.
func IsWeakKey(key []byte) bool {
	keyLen := len(key)
	if keyLen == 0 {
		return true
	}

	first := key[0]
	allSame := true
	for i := 1; i < keyLen; i++ {
		if key[i] != first {
			allSame = false
			break
		}
	}
	if allSame {
		return true
	}

	if hasLowEntropy(key) {
		return true
	}

	keyStr := strings.ToLower(string(key))
	for _, pattern := range weakPatterns {
		if strings.Contains(keyStr, pattern) {
			return true
		}
	}

	if keyLen >= 8 {
		sequential := true
		for i := 0; i < 7; i++ {
			if key[i+1] != key[i]+1 && key[i+1] != key[i]-1 {
				sequential = false
				break
			}
		}
		if sequential {
			return true
		}
	}

	return false
}

func hasLowEntropy(key []byte) bool {
	keyLen := len(key)
	if keyLen < 8 {
		return true
	}

	var uniqueCount int
	seen := make([]bool, 256)
	for _, b := range key {
		if !seen[b] {
			seen[b] = true
			uniqueCount++
		}
	}

	entropyRatio := float64(uniqueCount) / float64(keyLen)
	if entropyRatio < 0.3 {
		return true
	}

	hasLower, hasUpper, hasDigit, hasSpecial := false, false, false, false

	for _, b := range key {
		switch {
		case b >= 'a' && b <= 'z':
			hasLower = true
		case b >= 'A' && b <= 'Z':
			hasUpper = true
		case b >= '0' && b <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
		if hasLower && hasUpper && hasDigit && hasSpecial {
			break
		}
	}

	classCount := 0
	if hasLower {
		classCount++
	}
	if hasUpper {
		classCount++
	}
	if hasDigit {
		classCount++
	}
	if hasSpecial {
		classCount++
	}

	return classCount < 2
}
