package internal

import (
	"runtime"
	"strings"
)

func ZeroBytes(data []byte) {
	clear(data)
	runtime.KeepAlive(data)
}

var weakPatterns = map[string]struct{}{
	"password":    {},
	"12345678":    {},
	"qwerty":      {},
	"admin":       {},
	"test":        {},
	"default":     {},
	"example":     {},
	"demo":        {},
	"temp":        {},
	"secret":      {},
	"asdfgh":      {},
	"zxcvbn":      {},
	"123456":      {},
	"abcdef":      {},
	"qwertyuiop":  {},
	"1234567890":  {},
	"0987654321":  {},
	"passw0rd":    {},
	"letmein":     {},
	"welcome":     {},
}

func IsWeakKey(key []byte) bool {
	keyLen := len(key)
	if keyLen == 0 {
		return true
	}

	if isAllSameChar(key) {
		return true
	}

	if hasLowEntropy(key) {
		return true
	}

	if containsWeakPattern(key) {
		return true
	}

	if keyLen >= 8 && isSequential(key[:8]) {
		return true
	}

	return false
}

func isAllSameChar(key []byte) bool {
	if len(key) == 0 {
		return false
	}
	first := key[0]
	for _, b := range key[1:] {
		if b != first {
			return false
		}
	}
	return true
}

func containsWeakPattern(key []byte) bool {
	keyStr := strings.ToLower(string(key))
	for pattern := range weakPatterns {
		if strings.Contains(keyStr, pattern) {
			return true
		}
	}
	return false
}

func isSequential(key []byte) bool {
	if len(key) < 2 {
		return false
	}
	for i := 0; i < len(key)-1; i++ {
		if key[i+1] != key[i]+1 && key[i+1] != key[i]-1 {
			return false
		}
	}
	return true
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

	var hasLower, hasUpper, hasDigit, hasSpecial bool
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
			return false
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
