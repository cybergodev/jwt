package internal

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"sync"
)

type rsaSigningMethod struct {
	Name     string
	HashFunc crypto.Hash
	hashPool sync.Pool
}

func (r *rsaSigningMethod) Alg() string {
	return r.Name
}

func (r *rsaSigningMethod) Hash() crypto.Hash {
	return r.HashFunc
}

func (r *rsaSigningMethod) SignTo(dst []byte, signingString string, key any) (int, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return 0, errors.New("invalid key type: RSA signing requires *rsa.PrivateKey")
	}
	if rsaKey == nil {
		return 0, fmt.Errorf("RSA key cannot be nil")
	}

	if !r.HashFunc.Available() {
		return 0, fmt.Errorf("hash function %v not available", r.HashFunc)
	}

	hasher := r.hashPool.Get().(hash.Hash)
	defer r.hashPool.Put(hasher)
	hasher.Reset()
	hasher.Write(stringToBytes(signingString))

	var hashBuf [64]byte
	hashed := hasher.Sum(hashBuf[:0])

	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, r.HashFunc, hashed)
	if err != nil {
		return 0, fmt.Errorf("failed to sign with RSA: %w", err)
	}

	encodedLen := base64.RawURLEncoding.EncodedLen(len(signature))
	if len(dst) < encodedLen {
		return 0, fmt.Errorf("signature buffer too small: need %d, have %d", encodedLen, len(dst))
	}
	base64.RawURLEncoding.Encode(dst[:encodedLen], signature)
	return encodedLen, nil
}

func (r *rsaSigningMethod) Sign(signingString string, key any) (string, error) {
	var buf [684]byte // max RSA-4096: 512 bytes → 683 base64 chars
	n, err := r.SignTo(buf[:], signingString, key)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func (r *rsaSigningMethod) Verify(signingString string, signature string, key any) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		privKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return errors.New("invalid key type: RSA verification requires *rsa.PublicKey or *rsa.PrivateKey")
		}
		if privKey == nil {
			return fmt.Errorf("RSA key cannot be nil")
		}
		rsaKey = &privKey.PublicKey
	}

	if rsaKey == nil {
		return fmt.Errorf("RSA key cannot be nil")
	}

	if !r.HashFunc.Available() {
		return fmt.Errorf("hash function %v not available", r.HashFunc)
	}

	// Stack-allocated decode buffer for signature (max RSA sig: 512 bytes for RSA-4096)
	var sigBuf [512]byte
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

	expectedSigLen := rsaKey.Size()
	if len(sigBytes) != expectedSigLen {
		return errors.New("signature verification failed")
	}

	hasher := r.hashPool.Get().(hash.Hash)
	defer r.hashPool.Put(hasher)
	hasher.Reset()
	hasher.Write(stringToBytes(signingString))

	var hashBuf [64]byte
	hashed := hasher.Sum(hashBuf[:0])

	err = rsa.VerifyPKCS1v15(rsaKey, r.HashFunc, hashed, sigBytes)
	if err != nil {
		return errors.New("signature verification failed")
	}

	return nil
}

func newRSAMethod(name string, hash crypto.Hash) *rsaSigningMethod {
	return &rsaSigningMethod{
		Name:     name,
		HashFunc: hash,
		hashPool: sync.Pool{
			New: func() any { return hash.New() },
		},
	}
}

var (
	rsaRS256 = newRSAMethod("RS256", crypto.SHA256)
	rsaRS384 = newRSAMethod("RS384", crypto.SHA384)
	rsaRS512 = newRSAMethod("RS512", crypto.SHA512)
)

type rsaPSSSigningMethod struct {
	Name     string
	HashFunc crypto.Hash
	opts     rsa.PSSOptions
	hashPool sync.Pool
}

func (r *rsaPSSSigningMethod) Alg() string {
	return r.Name
}

func (r *rsaPSSSigningMethod) Hash() crypto.Hash {
	return r.HashFunc
}

func (r *rsaPSSSigningMethod) SignTo(dst []byte, signingString string, key any) (int, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return 0, errors.New("invalid key type: RSA-PSS signing requires *rsa.PrivateKey")
	}
	if rsaKey == nil {
		return 0, fmt.Errorf("RSA key cannot be nil")
	}

	if !r.HashFunc.Available() {
		return 0, fmt.Errorf("hash function %v not available", r.HashFunc)
	}

	hasher := r.hashPool.Get().(hash.Hash)
	defer r.hashPool.Put(hasher)
	hasher.Reset()
	hasher.Write(stringToBytes(signingString))

	var hashBuf [64]byte
	hashed := hasher.Sum(hashBuf[:0])

	signature, err := rsa.SignPSS(rand.Reader, rsaKey, r.HashFunc, hashed, &r.opts)
	if err != nil {
		return 0, fmt.Errorf("failed to sign with RSA-PSS: %w", err)
	}

	encodedLen := base64.RawURLEncoding.EncodedLen(len(signature))
	if len(dst) < encodedLen {
		return 0, fmt.Errorf("signature buffer too small: need %d, have %d", encodedLen, len(dst))
	}
	base64.RawURLEncoding.Encode(dst[:encodedLen], signature)
	return encodedLen, nil
}

func (r *rsaPSSSigningMethod) Sign(signingString string, key any) (string, error) {
	var buf [684]byte // max RSA-4096: 512 bytes → 683 base64 chars
	n, err := r.SignTo(buf[:], signingString, key)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func (r *rsaPSSSigningMethod) Verify(signingString string, signature string, key any) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		privKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return errors.New("invalid key type: RSA-PSS verification requires *rsa.PublicKey or *rsa.PrivateKey")
		}
		if privKey == nil {
			return fmt.Errorf("RSA key cannot be nil")
		}
		rsaKey = &privKey.PublicKey
	}

	if rsaKey == nil {
		return fmt.Errorf("RSA key cannot be nil")
	}

	if !r.HashFunc.Available() {
		return fmt.Errorf("hash function %v not available", r.HashFunc)
	}

	// Stack-allocated decode buffer for signature (max RSA sig: 512 bytes for RSA-4096)
	var sigBuf [512]byte
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

	expectedSigLen := rsaKey.Size()
	if len(sigBytes) != expectedSigLen {
		return errors.New("signature verification failed")
	}

	hasher := r.hashPool.Get().(hash.Hash)
	defer r.hashPool.Put(hasher)
	hasher.Reset()
	hasher.Write(stringToBytes(signingString))

	var hashBuf [64]byte
	hashed := hasher.Sum(hashBuf[:0])

	err = rsa.VerifyPSS(rsaKey, r.HashFunc, hashed, sigBytes, &r.opts)
	if err != nil {
		return errors.New("signature verification failed")
	}

	return nil
}

func newRSSMethod(name string, hash crypto.Hash) *rsaPSSSigningMethod {
	return &rsaPSSSigningMethod{
		Name:     name,
		HashFunc: hash,
		opts:     rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash},
		hashPool: sync.Pool{
			New: func() any { return hash.New() },
		},
	}
}

var (
	rsaPS256 = newRSSMethod("PS256", crypto.SHA256)
	rsaPS384 = newRSSMethod("PS384", crypto.SHA384)
	rsaPS512 = newRSSMethod("PS512", crypto.SHA512)
)
