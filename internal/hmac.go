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
	if decodedLen > len(sigBuf) {
		return errors.New("signature verification failed")
	}
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

func (h *hmacSigningMethod) SignTo(dst []byte, signingString string, key any) (int, error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return 0, fmt.Errorf("HMAC key must be []byte, got %T", key)
	}

	if !h.HashFunc.Available() {
		return 0, fmt.Errorf("hash function %v not available", h.HashFunc)
	}

	hasher := h.getHasher(keyBytes)
	defer h.putHasher(hasher, keyBytes)
	hasher.Reset()
	hasher.Write(stringToBytes(signingString))

	var hashBuf [64]byte
	hashed := hasher.Sum(hashBuf[:0])

	encodedLen := base64.RawURLEncoding.EncodedLen(len(hashed))
	if len(dst) < encodedLen {
		return 0, fmt.Errorf("signature buffer too small: need %d, have %d", encodedLen, len(dst))
	}
	base64.RawURLEncoding.Encode(dst[:encodedLen], hashed)
	return encodedLen, nil
}

var (
	hmacHS256 = &hmacSigningMethod{"HS256", crypto.SHA256, sync.Pool{}}
	hmacHS384 = &hmacSigningMethod{"HS384", crypto.SHA384, sync.Pool{}}
	hmacHS512 = &hmacSigningMethod{"HS512", crypto.SHA512, sync.Pool{}}
)

// ClearHMACCaches drains all HMAC hasher pools, allowing GC to reclaim
// hasher objects that may retain secret key material in their internal state.
func ClearHMACCaches() {
	hmacHS256.drainPool()
	hmacHS384.drainPool()
	hmacHS512.drainPool()
}

// drainPool removes all entries from the pool so they can be garbage collected.
func (h *hmacSigningMethod) drainPool() {
	for {
		if h.pool.Get() == nil {
			return
		}
	}
}
