package internal

import (
	"crypto"
	"crypto/hmac"
	"crypto/subtle"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"sync"
)

type hmacSigningMethod struct {
	Name     string
	HashFunc crypto.Hash
	pool     sync.Pool
}

// hasherEntry wraps a pooled HMAC hasher with its associated key
// for identity verification on retrieval.
type hasherEntry struct {
	key    []byte
	hasher hash.Hash
}

func (h *hmacSigningMethod) getHasher(key []byte) hash.Hash {
	if v := h.pool.Get(); v != nil {
		entry := v.(*hasherEntry)
		if len(entry.key) == len(key) && subtle.ConstantTimeCompare(entry.key, key) == 1 {
			return entry.hasher
		}
	}
	return hmac.New(h.HashFunc.New, key)
}

func (h *hmacSigningMethod) putHasher(hasher hash.Hash, key []byte) {
	h.pool.Put(&hasherEntry{key: key, hasher: hasher})
}

func (h *hmacSigningMethod) Verify(signingString string, signature string, key any) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("HMAC key must be []byte, got %T", key)
	}

	if !h.HashFunc.Available() {
		return fmt.Errorf("hash function %v not available", h.HashFunc)
	}

	// Stack-allocated decode buffer for signature (max HMAC sig: 64 bytes for SHA512)
	var sigBuf [64]byte
	decodedLen := base64.RawURLEncoding.DecodedLen(len(signature))
	sigBytes := sigBuf[:decodedLen]
	n, err := base64.RawURLEncoding.Decode(sigBytes, stringToBytes(signature))
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	sigBytes = sigBytes[:n]

	if len(sigBytes) != h.HashFunc.Size() {
		return errors.New("signature verification failed")
	}

	hasher := h.getHasher(keyBytes)
	defer h.putHasher(hasher, keyBytes)
	hasher.Reset()
	hasher.Write(stringToBytes(signingString))

	// Stack-allocated hash output buffer
	var hashBuf [64]byte
	if !hmac.Equal(sigBytes, hasher.Sum(hashBuf[:0])) {
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

	hasher := h.getHasher(keyBytes)
	defer h.putHasher(hasher, keyBytes)
	hasher.Reset()
	hasher.Write(stringToBytes(signingString))

	// Stack-allocated hash output buffer
	var hashBuf [64]byte
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(hashBuf[:0])), nil
}

func (h *hmacSigningMethod) Alg() string {
	return h.Name
}

func (h *hmacSigningMethod) Hash() crypto.Hash {
	return h.HashFunc
}

var (
	hmacHS256 = &hmacSigningMethod{"HS256", crypto.SHA256, sync.Pool{}}
	hmacHS384 = &hmacSigningMethod{"HS384", crypto.SHA384, sync.Pool{}}
	hmacHS512 = &hmacSigningMethod{"HS512", crypto.SHA512, sync.Pool{}}
)
