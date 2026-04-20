package internal

import (
	"bytes"
	"runtime"
	"strings"
)

// Key validation constants
const (
	// entropyRatioThreshold is the minimum ratio of unique bytes to total bytes
	entropyRatioThreshold = 0.3
	// sequentialCheckLength is the minimum key length to check for sequential patterns
	sequentialCheckLength = 8
	// minEntropyKeyLength is the minimum key length for entropy calculation
	minEntropyKeyLength = 8
)

func ZeroBytes(data []byte) {
	clear(data)
	runtime.KeepAlive(data)
}

var weakPatterns = map[string]struct{}{
	"password":   {},
	"12345678":   {},
	"qwerty":     {},
	"admin":      {},
	"test":       {},
	"default":    {},
	"example":    {},
	"demo":       {},
	"temp":       {},
	"secret":     {},
	"asdfgh":     {},
	"zxcvbn":     {},
	"123456":     {},
	"abcdef":     {},
	"qwertyuiop": {},
	"1234567890": {},
	"0987654321": {},
	"passw0rd":   {},
	"letmein":    {},
	"welcome":    {},
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

	// Check for sequential patterns using sliding window for better coverage
	// This catches patterns like "abcdefghRANDOM" that would be missed by only checking prefix
	if keyLen >= sequentialCheckLength {
		if hasSequentialPattern(key, sequentialCheckLength) {
			return true
		}
	}

	// Check for repeating patterns like "abcabcabc"
	if keyLen >= 6 {
		if hasRepeatingPattern(key, 3) {
			return true
		}
	}

	return false
}

// hasRepeatingPattern checks if the key contains repeating patterns.
// For example, "abcabcabc" has a repeating pattern of length 3.
func hasRepeatingPattern(key []byte, minPatternLen int) bool {
	keyLen := len(key)
	if keyLen < minPatternLen*2 {
		return false
	}

	// Try different pattern lengths
	for patternLen := minPatternLen; patternLen <= keyLen/2; patternLen++ {
		pattern := key[:patternLen]
		repeats := 1

		// Check how many times this pattern repeats
		for i := patternLen; i+patternLen <= keyLen; i += patternLen {
			if bytes.Equal(key[i:i+patternLen], pattern) {
				repeats++
				// Found at least 2 full repetitions
				if repeats >= 2 {
					return true
				}
			} else {
				break
			}
		}
	}

	return false
}

// hasSequentialPattern checks if any sequentialCheckLength-byte window contains sequential characters
func hasSequentialPattern(key []byte, windowSize int) bool {
	keyLen := len(key)
	if keyLen < windowSize {
		return false
	}

	// Check each window position
	for i := 0; i <= keyLen-windowSize; i++ {
		if isSequential(key[i : i+windowSize]) {
			return true
		}
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
	if keyLen < minEntropyKeyLength {
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
	if entropyRatio < entropyRatioThreshold {
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
