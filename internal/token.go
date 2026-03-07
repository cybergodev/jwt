package internal

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
)

const (
	// TokenIDLength is the length of the random portion of a token ID in bytes.
	TokenIDLength = 16
	// TokenIDPrefix is the prefix added to all generated token IDs.
	TokenIDPrefix = "tok_"
	// tokenIDResultLen is the total length of a token ID.
	tokenIDResultLen = len(TokenIDPrefix) + TokenIDLength*2
)

// tokenIDBufPool pools byte slices for token ID generation.
var tokenIDBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, TokenIDLength+tokenIDResultLen)
		return &buf
	},
}

// GenerateTokenID generates a unique token ID using cryptographic random bytes.
// The ID has the format "tok_" followed by 32 hexadecimal characters.
func GenerateTokenID() (string, error) {
	bufPtr := tokenIDBufPool.Get().(*[]byte)
	defer tokenIDBufPool.Put(bufPtr)

	buf := *bufPtr
	randomBytes := buf[:TokenIDLength]
	result := buf[TokenIDLength : TokenIDLength+tokenIDResultLen]

	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}

	copy(result, TokenIDPrefix)
	hex.Encode(result[len(TokenIDPrefix):], randomBytes)

	return string(result), nil
}
