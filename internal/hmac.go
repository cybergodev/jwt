package internal

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
)

type hmacSigningMethod struct {
	Name     string
	HashFunc crypto.Hash
}

// sigBufPool pools byte slices for signature operations.
// HMAC signatures are at most 64 bytes (HS512), with base64 encoding ~88 bytes.
var sigBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 256)
		return &buf
	},
}

func getSigBuf() *[]byte {
	return sigBufPool.Get().(*[]byte)
}

func putSigBuf(buf *[]byte) {
	if cap(*buf) <= 512 {
		*buf = (*buf)[:0]
		sigBufPool.Put(buf)
	}
}

func (h *hmacSigningMethod) Verify(signingString string, signature string, key any) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("HMAC key must be []byte, got %T", key)
	}

	if !h.HashFunc.Available() {
		return fmt.Errorf("hash function %v not available", h.HashFunc)
	}

	bufPtr := getSigBuf()
	defer putSigBuf(bufPtr)

	sigLen := base64.RawURLEncoding.DecodedLen(len(signature))
	if cap(*bufPtr) < sigLen {
		*bufPtr = make([]byte, 0, sigLen)
	}

	sigBytes := (*bufPtr)[:sigLen]
	n, err := base64.RawURLEncoding.Decode(sigBytes, stringToBytes(signature))
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	sigBytes = sigBytes[:n]

	// Validate signature length matches hash output size
	// This provides early failure and consistent timing
	expectedSigLen := h.HashFunc.Size()
	if len(sigBytes) != expectedSigLen {
		return errors.New("signature verification failed")
	}

	hasher := hmac.New(h.HashFunc.New, keyBytes)
	hasher.Write(stringToBytes(signingString))
	expectedSigBytes := hasher.Sum(nil)

	if !hmac.Equal(sigBytes, expectedSigBytes) {
		return errors.New("signature verification failed")
	}

	return nil
}

func (h *hmacSigningMethod) Sign(signingString string, key any) (string, error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return "", fmt.Errorf("HMAC key must be []byte, got %T", key)
	}

	if !h.HashFunc.Available() {
		return "", fmt.Errorf("hash function %v not available", h.HashFunc)
	}

	hasher := hmac.New(h.HashFunc.New, keyBytes)
	hasher.Write(stringToBytes(signingString))

	bufPtr := getSigBuf()
	defer putSigBuf(bufPtr)

	hashSize := h.HashFunc.Size()
	encodedLen := base64.RawURLEncoding.EncodedLen(hashSize)
	totalLen := hashSize + encodedLen

	if cap(*bufPtr) < totalLen {
		*bufPtr = make([]byte, 0, totalLen)
	}

	// Use buffer for both hash and encoded result
	buf := (*bufPtr)[:totalLen]
	signature := buf[:hashSize]
	hasher.Sum(signature[:0])

	// Encode to base64 in the same buffer's remaining space
	encoded := buf[hashSize : hashSize+encodedLen]
	base64.RawURLEncoding.Encode(encoded, signature)

	// Must copy for external return (buffer will be returned to pool)
	return string(encoded), nil
}

func (h *hmacSigningMethod) Alg() string {
	return h.Name
}

func (h *hmacSigningMethod) Hash() crypto.Hash {
	return h.HashFunc
}

var (
	hmacHS256 = &hmacSigningMethod{"HS256", crypto.SHA256}
	hmacHS384 = &hmacSigningMethod{"HS384", crypto.SHA384}
	hmacHS512 = &hmacSigningMethod{"HS512", crypto.SHA512}
)
