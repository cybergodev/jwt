package internal

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/subtle"
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

// hasherResult pairs a hasher with the key it was created for,
// so putHasher can reuse the existing key slice instead of allocating a copy.
type hasherResult struct {
	hasher hash.Hash
	key    []byte       // key identity for pool storage
	entry  *hasherEntry // reused entry struct to avoid allocation in putHasher
}

func (h *hmacSigningMethod) getHasher(key []byte) hasherResult {
	if v := h.pool.Get(); v != nil {
		entry := v.(*hasherEntry)
		if len(entry.key) == len(key) && subtle.ConstantTimeCompare(entry.key, key) == 1 {
			return hasherResult{hasher: entry.hasher, key: entry.key, entry: entry}
		}
		ZeroBytes(entry.key)
		// Reuse the entry struct for the new hasher to avoid allocation in putHasher.
		keyCopy := make([]byte, len(key))
		copy(keyCopy, key)
		return hasherResult{
			hasher: hmac.New(h.HashFunc.New, key),
			key:    keyCopy,
			entry:  entry,
		}
	}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return hasherResult{
		hasher: hmac.New(h.HashFunc.New, key),
		key:    keyCopy,
	}
}

func (h *hmacSigningMethod) putHasher(r hasherResult) {
	if r.entry != nil {
		r.entry.key = r.key
		r.entry.hasher = r.hasher
		h.pool.Put(r.entry)
	} else {
		h.pool.Put(&hasherEntry{key: r.key, hasher: r.hasher})
	}
}

func (h *hmacSigningMethod) Verify(signingString string, signature string, key any) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return errors.New("invalid key type: HMAC requires []byte key")
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

	hr := h.getHasher(keyBytes)
	defer h.putHasher(hr)
	hr.hasher.Reset()
	hr.hasher.Write(stringToBytes(signingString))

	// Stack-allocated hash output buffer
	var hashBuf [64]byte
	if !hmac.Equal(sigBytes, hr.hasher.Sum(hashBuf[:0])) {
		return errors.New("signature verification failed")
	}

	return nil
}

// VerifyHMAC is a type-specialized variant of Verify that accepts []byte directly,
// avoiding the interface boxing overhead.
func (h *hmacSigningMethod) VerifyHMAC(signingString string, signature string, key []byte) error {
	if !h.HashFunc.Available() {
		return fmt.Errorf("hash function %v not available", h.HashFunc)
	}

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

	hr := h.getHasher(key)
	defer h.putHasher(hr)
	hr.hasher.Reset()
	hr.hasher.Write(stringToBytes(signingString))

	var hashBuf [64]byte
	if !hmac.Equal(sigBytes, hr.hasher.Sum(hashBuf[:0])) {
		return errors.New("signature verification failed")
	}

	return nil
}

func (h *hmacSigningMethod) Sign(signingString string, key any) (string, error) {
	var buf [86]byte // max HS512: 64 bytes → 86 base64 chars
	n, err := h.SignTo(buf[:], signingString, key)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
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
		return 0, errors.New("invalid key type: HMAC requires []byte key")
	}

	if !h.HashFunc.Available() {
		return 0, fmt.Errorf("hash function %v not available", h.HashFunc)
	}

	hr := h.getHasher(keyBytes)
	defer h.putHasher(hr)
	hr.hasher.Reset()
	hr.hasher.Write(stringToBytes(signingString))

	var hashBuf [64]byte
	hashed := hr.hasher.Sum(hashBuf[:0])

	encodedLen := base64.RawURLEncoding.EncodedLen(len(hashed))
	if len(dst) < encodedLen {
		return 0, fmt.Errorf("signature buffer too small: need %d, have %d", encodedLen, len(dst))
	}
	base64.RawURLEncoding.Encode(dst[:encodedLen], hashed)
	return encodedLen, nil
}

// SignToHMAC is a type-specialized variant of SignTo that accepts []byte directly,
// avoiding the interface boxing overhead that causes key escape.
func (h *hmacSigningMethod) SignToHMAC(dst []byte, signingString string, key []byte) (int, error) {
	if !h.HashFunc.Available() {
		return 0, fmt.Errorf("hash function %v not available", h.HashFunc)
	}

	hr := h.getHasher(key)
	defer h.putHasher(hr)
	hr.hasher.Reset()
	hr.hasher.Write(stringToBytes(signingString))

	var hashBuf [64]byte
	hashed := hr.hasher.Sum(hashBuf[:0])

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

// drainPool removes all entries from the pool, zeroing key material and resetting
// hashers before allowing GC to reclaim them.
func (h *hmacSigningMethod) drainPool() {
	for {
		v := h.pool.Get()
		if v == nil {
			return
		}
		entry := v.(*hasherEntry)
		ZeroBytes(entry.key)
		entry.hasher.Reset()
	}
}
