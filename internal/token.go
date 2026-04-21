package internal

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const (
	// TokenIDLength is the length of the random portion of a token ID in bytes.
	TokenIDLength = 16
	// TokenIDPrefix is the prefix added to all generated token IDs.
	TokenIDPrefix = "tok_"
	// tokenIDResultLen is the total length of a token ID.
	tokenIDResultLen = len(TokenIDPrefix) + TokenIDLength*2
)

// GenerateTokenID generates a unique token ID using cryptographic random bytes.
// The ID has the format "tok_" followed by 32 hexadecimal characters.
// Uses stack-allocated arrays instead of pooled buffers because the fixed
// result size (36 bytes) makes pool Get/Put overhead (~60ns) more expensive
// than a single string() copy.
func GenerateTokenID() (string, error) {
	var randomBytes [TokenIDLength]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}

	var buf [tokenIDResultLen]byte
	copy(buf[:len(TokenIDPrefix)], TokenIDPrefix)
	hex.Encode(buf[len(TokenIDPrefix):], randomBytes[:])

	return string(buf[:]), nil
}
