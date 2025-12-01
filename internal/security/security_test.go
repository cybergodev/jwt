package security

import (
	"testing"
)

func TestIsWeakKeyCommonPatterns(t *testing.T) {
	weakKeys := [][]byte{
		[]byte("password123456789012345678901234"),
		[]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		[]byte("12345678901234567890123456789012"),
		[]byte("qwertyuiopasdfghjklzxcvbnm123456"),
	}

	for i, key := range weakKeys {
		if !IsWeakKey(key) {
			t.Errorf("Test %d: Key should be detected as weak: %s", i, string(key))
		}
	}
}

func TestIsWeakKeyStrongKeys(t *testing.T) {
	strongKeys := [][]byte{
		[]byte("Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"),
		[]byte("aB3$fG7*kL9#pQ2&vX5!zC8@mN4%rT6^wY1+eH0-iJ3~oU7$bD9#gK2&sF5*nM8@"),
	}

	for i, key := range strongKeys {
		if IsWeakKey(key) {
			t.Errorf("Test %d: Key should not be detected as weak: %s", i, string(key))
		}
	}
}

func TestIsWeakKeyEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
		want bool
	}{
		{"empty key", []byte{}, true},
		{"all same character", []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), true},
		{"sequential ascending", []byte("abcdefghijklmnopqrstuvwxyz123456"), true},
		{"low entropy", []byte("ababababababababababababababababab"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsWeakKey(tt.key)
			if result != tt.want {
				t.Errorf("IsWeakKey() = %v, want %v", result, tt.want)
			}
		})
	}
}

func TestZeroBytes(t *testing.T) {
	data := []byte("sensitive-data-to-zero")

	ZeroBytes(data)

	// Check that data has been zeroed
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}

	if !allZero {
		t.Error("ZeroBytes should zero all bytes")
	}
}
