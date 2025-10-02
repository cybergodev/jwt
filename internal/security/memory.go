package security

import (
	"crypto/rand"
	mathrand "math/rand"
	"runtime"
	"strings"
	"sync"
	"time"
)

// SecureBytes represents a secure byte slice that will be zeroed when no longer needed
type SecureBytes struct {
	data []byte
	mu   sync.Mutex // Protect against concurrent access during cleanup
}

// NewSecureBytesFromSlice creates a secure byte slice from existing data
func NewSecureBytesFromSlice(data []byte) *SecureBytes {
	secure := &SecureBytes{
		data: make([]byte, len(data)),
	}
	copy(secure.data, data)

	if len(data) > 256 {
		runtime.SetFinalizer(secure, (*SecureBytes).destroy)
	}

	return secure
}

// Bytes returns the underlying byte slice (use with caution)
func (s *SecureBytes) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

// Copy creates a secure copy of the data
func (s *SecureBytes) Copy() *SecureBytes {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		return &SecureBytes{}
	}
	return NewSecureBytesFromSlice(s.data)
}

// Destroy securely zeros the memory and marks for cleanup
func (s *SecureBytes) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.destroy()
	runtime.SetFinalizer(s, nil)
}

func (s *SecureBytes) destroy() {
	if s.data != nil {
		ZeroBytes(s.data)
		s.data = nil
	}
}

// ZeroBytes securely zeros a byte slice
func ZeroBytes(data []byte) {
	if len(data) == 0 {
		return
	}

	for i := range data {
		data[i] = 0
	}

	for i := range data {
		data[i] = 0xFF
	}

	for i := range data {
		data[i] = 0
	}

	runtime.KeepAlive(data)
}

// SecureCompare performs constant-time comparison of two byte slices
func SecureCompare(a, b []byte) bool {
	lenA := len(a)
	lenB := len(b)

	if lenA == lenB {
		var result byte
		for i := 0; i < lenA; i++ {
			result |= a[i] ^ b[i]
		}
		return result == 0
	}

	maxLen := lenA
	if lenB > maxLen {
		maxLen = lenB
	}

	var result byte
	for i := 0; i < maxLen; i++ {
		var aVal, bVal byte
		if i < lenA {
			aVal = a[i]
		}
		if i < lenB {
			bVal = b[i]
		}
		result |= aVal ^ bVal
	}

	return result == 0 && lenA == lenB
}

// RandomDelay adds random delay to prevent timing attacks
func RandomDelay() {
	delay := time.Duration(mathrand.Intn(50)+1) * time.Microsecond
	time.Sleep(delay)
}

// SecureRandomDelay adds cryptographically secure random delay for critical operations
func SecureRandomDelay() {
	var delayBytes [1]byte
	rand.Read(delayBytes[:])
	delay := time.Duration(10+int(delayBytes[0])%90) * time.Microsecond
	time.Sleep(delay)
}

// IsWeakKey checks for weak keys with insufficient entropy using comprehensive analysis
func IsWeakKey(key []byte) bool {
	if len(key) == 0 {
		return true
	}

	// Check for all-zero key
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return true
	}

	// Check for repeated patterns (simple entropy check)
	if len(key) >= 4 {
		pattern := key[0]
		repeated := true
		for _, b := range key {
			if b != pattern {
				repeated = false
				break
			}
		}
		if repeated {
			return true
		}
	}

	// Enhanced entropy analysis - check for low entropy patterns
	if hasLowEntropy(key) {
		return true
	}

	// Check for common weak patterns (case-insensitive)
	keyStr := strings.ToLower(string(key))
	weakPatterns := []string{
		"12345678", "87654321", "11111111", "00000000", "aaaaaaaa",
		"abcdefgh", "qwertyui", "asdfghjk", "zxcvbnm", "qwerty",
		"letmein", "welcome", "monkey", "dragon", "master",
		"sunshine", "iloveyou", "princess", "football", "charlie",
		"default", "example", "sample", "demo", "guest", "public",
		"private", "secure", "unsafe", "temp", "temporary",
		"password", "test", "admin", "user", "token",
	}

	for _, pattern := range weakPatterns {
		if strings.Contains(keyStr, pattern) {
			return true
		}
	}

	// Check for keyboard patterns
	if hasKeyboardPattern(keyStr) {
		return true
	}

	// Check for simple patterns (ascending/descending sequences)
	if len(key) >= 8 {
		ascending := true
		descending := true
		for i := 1; i < len(key) && i < 8; i++ {
			if key[i] != key[i-1]+1 {
				ascending = false
			}
			if key[i] != key[i-1]-1 {
				descending = false
			}
		}
		if ascending || descending {
			return true
		}
	}

	// Check for short repeated patterns (e.g., "abcabc...", "123123...")
	if len(key) >= 6 {
		for patternLen := 2; patternLen <= 4; patternLen++ {
			if len(key) >= patternLen*3 { // At least 3 repetitions
				pattern := key[:patternLen]
				isRepeated := true
				for i := patternLen; i < len(key); i += patternLen {
					end := i + patternLen
					if end > len(key) {
						// Check remaining characters against pattern prefix
						remaining := key[i:]
						if !bytesEqual(remaining, pattern[:len(remaining)]) {
							isRepeated = false
							break
						}
					} else {
						// Check full pattern
						if !bytesEqual(key[i:end], pattern) {
							isRepeated = false
							break
						}
					}
				}
				if isRepeated {
					return true
				}
			}
		}
	}

	return false
}

// hasLowEntropy performs comprehensive entropy analysis
func hasLowEntropy(key []byte) bool {
	if len(key) < 8 {
		return true
	}

	// Count unique bytes
	uniqueBytes := make(map[byte]bool)
	for _, b := range key {
		uniqueBytes[b] = true
	}

	// If less than 30% unique characters, consider low entropy
	entropyRatio := float64(len(uniqueBytes)) / float64(len(key))
	if entropyRatio < 0.3 {
		return true
	}

	// Check for character class diversity
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSpecial := false

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
	}

	// Count character classes
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

	// For keys longer than 32 chars, require at least 3 character classes
	// For shorter keys, require at least 2 character classes
	minClasses := 2
	if len(key) >= 32 {
		minClasses = 3
	}

	return classCount < minClasses
}

// hasKeyboardPattern detects common keyboard patterns
func hasKeyboardPattern(keyStr string) bool {
	keyboardPatterns := []string{
		"qwertyuiop", "asdfghjkl", "zxcvbnm",
		"1234567890", "0987654321",
		"qwerty", "asdfgh", "zxcvbn",
		"poiuytrewq", "lkjhgfdsa", "mnbvcxz",
		"qwertz", "azerty", // International layouts
		"dvorak", "colemak", // Alternative layouts
	}

	for _, pattern := range keyboardPatterns {
		if strings.Contains(keyStr, pattern) {
			return true
		}
		// Check reverse pattern
		if strings.Contains(keyStr, reverseString(pattern)) {
			return true
		}
	}

	return false
}

// reverseString reverses a string
func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// bytesEqual compares two byte slices for equality
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
