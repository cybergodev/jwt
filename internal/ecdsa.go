package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"sync"
)

type ecdsaSigningMethod struct {
	Name     string
	HashFunc crypto.Hash
	KeySize  int
	sigPool  sync.Pool
	hashPool sync.Pool
}

func newECDSAMethod(name string, hash crypto.Hash, keySize int) *ecdsaSigningMethod {
	m := &ecdsaSigningMethod{
		Name:     name,
		HashFunc: hash,
		KeySize:  keySize,
		sigPool: sync.Pool{
			New: func() any {
				buf := make([]byte, 2*keySize)
				return &buf
			},
		},
		hashPool: sync.Pool{
			New: func() any {
				return hash.New()
			},
		},
	}
	return m
}

func (e *ecdsaSigningMethod) Alg() string {
	return e.Name
}

func (e *ecdsaSigningMethod) Hash() crypto.Hash {
	return e.HashFunc
}

func (e *ecdsaSigningMethod) SignTo(dst []byte, signingString string, key any) (int, error) {
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return 0, fmt.Errorf("ECDSA key must be *ecdsa.PrivateKey, got %T", key)
	}
	if ecdsaKey == nil {
		return 0, fmt.Errorf("ECDSA key cannot be nil")
	}

	if !e.HashFunc.Available() {
		return 0, fmt.Errorf("hash function %v not available", e.HashFunc)
	}

	hasher := e.hashPool.Get().(hash.Hash)
	defer e.hashPool.Put(hasher)
	hasher.Reset()
	hasher.Write(stringToBytes(signingString))

	var hashBuf [64]byte
	hashed := hasher.Sum(hashBuf[:0])

	sigR, sigS, err := ecdsa.Sign(rand.Reader, ecdsaKey, hashed)
	if err != nil {
		return 0, fmt.Errorf("failed to sign with ECDSA: %w", err)
	}

	keyBytes := e.KeySize
	sigPtr := e.sigPool.Get().(*[]byte)
	defer e.sigPool.Put(sigPtr)

	sig := (*sigPtr)[:2*keyBytes]
	sigR.FillBytes(sig[:keyBytes])
	sigS.FillBytes(sig[keyBytes:])

	encodedLen := base64.RawURLEncoding.EncodedLen(len(sig))
	if len(dst) < encodedLen {
		return 0, fmt.Errorf("signature buffer too small: need %d, have %d", encodedLen, len(dst))
	}
	base64.RawURLEncoding.Encode(dst[:encodedLen], sig)
	return encodedLen, nil
}

var (
	// bigIntPool pools big.Int objects for ECDSA verification.
	bigIntPool = sync.Pool{
		New: func() any {
			return new(big.Int)
		},
	}
)

func (e *ecdsaSigningMethod) Sign(signingString string, key any) (string, error) {
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("ECDSA key must be *ecdsa.PrivateKey, got %T", key)
	}
	if ecdsaKey == nil {
		return "", fmt.Errorf("ECDSA key cannot be nil")
	}

	if !e.HashFunc.Available() {
		return "", fmt.Errorf("hash function %v not available", e.HashFunc)
	}

	hasher := e.hashPool.Get().(hash.Hash)
	defer e.hashPool.Put(hasher)
	hasher.Reset()
	hasher.Write(stringToBytes(signingString))

	var hashBuf [64]byte
	hashed := hasher.Sum(hashBuf[:0])

	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hashed)
	if err != nil {
		return "", fmt.Errorf("failed to sign with ECDSA: %w", err)
	}

	keyBytes := e.KeySize
	sigPtr := e.sigPool.Get().(*[]byte)
	defer e.sigPool.Put(sigPtr)

	sig := (*sigPtr)[:2*keyBytes]
	r.FillBytes(sig[:keyBytes])
	s.FillBytes(sig[keyBytes:])

	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func (e *ecdsaSigningMethod) Verify(signingString string, signature string, key any) error {
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		privKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("ECDSA key must be *ecdsa.PublicKey or *ecdsa.PrivateKey, got %T", key)
		}
		if privKey == nil {
			return fmt.Errorf("ECDSA key cannot be nil")
		}
		ecdsaKey = &privKey.PublicKey
	}

	if ecdsaKey == nil {
		return fmt.Errorf("ECDSA key cannot be nil")
	}

	if !e.HashFunc.Available() {
		return fmt.Errorf("hash function %v not available", e.HashFunc)
	}

	// Stack-allocated decode buffer for signature (max ECDSA sig: 132 bytes for ES512)
	var sigBuf [132]byte
	decodedLen := base64.RawURLEncoding.DecodedLen(len(signature))
	if decodedLen > len(sigBuf) {
		return errors.New("signature verification failed")
	}
	decoded := sigBuf[:decodedLen]
	n, err := base64.RawURLEncoding.Decode(decoded, stringToBytes(signature))
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	sigBytes := decoded[:n]

	keyBytes := e.KeySize
	if len(sigBytes) != 2*keyBytes {
		return errors.New("signature verification failed")
	}

	// Use pooled big.Int to avoid heap allocation
	r := bigIntPool.Get().(*big.Int)
	s := bigIntPool.Get().(*big.Int)
	defer func() {
		r.SetInt64(0)
		s.SetInt64(0)
		bigIntPool.Put(r)
		bigIntPool.Put(s)
	}()

	r.SetBytes(sigBytes[:keyBytes])
	s.SetBytes(sigBytes[keyBytes:])

	hasher := e.hashPool.Get().(hash.Hash)
	defer e.hashPool.Put(hasher)
	hasher.Reset()
	hasher.Write(stringToBytes(signingString))

	var hashBuf [64]byte
	hashed := hasher.Sum(hashBuf[:0])

	valid := ecdsa.Verify(ecdsaKey, hashed, r, s)
	if !valid {
		return errors.New("signature verification failed")
	}

	return nil
}

var (
	ecdsaES256 = newECDSAMethod("ES256", crypto.SHA256, 32)
	ecdsaES384 = newECDSAMethod("ES384", crypto.SHA384, 48)
	ecdsaES512 = newECDSAMethod("ES512", crypto.SHA512, 66)
)
