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

// tokenIDBufPool pools byte slices used for token ID generation.
// Avoids two heap allocations per token creation.
var tokenIDBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, tokenIDResultLen)
		return &buf
	},
}

// randomBufPool pools the random bytes slice used in token ID generation.
var randomBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, TokenIDLength)
		return &buf
	},
}

// GenerateTokenID generates a unique token ID using cryptographic random bytes.
// The ID has the format "tok_" followed by 32 hexadecimal characters.
func GenerateTokenID() (string, error) {
	randomBytes := randomBufPool.Get().(*[]byte)
	defer randomBufPool.Put(randomBytes)

	if _, err := rand.Read(*randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}

	bufPtr := tokenIDBufPool.Get().(*[]byte)
	defer tokenIDBufPool.Put(bufPtr)

	buf := (*bufPtr)[:tokenIDResultLen]
	copy(buf, TokenIDPrefix)
	hex.Encode(buf[len(TokenIDPrefix):], *randomBytes)

	result := string(buf)
	return result, nil
}
