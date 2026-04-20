package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

type ecdsaSigningMethod struct {
	Name     string
	HashFunc crypto.Hash
	KeySize  int
}

func (e *ecdsaSigningMethod) Alg() string {
	return e.Name
}

func (e *ecdsaSigningMethod) Hash() crypto.Hash {
	return e.HashFunc
}

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

	hasher := e.HashFunc.New()
	hasher.Write(stringToBytes(signingString))
	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hashed)
	if err != nil {
		return "", fmt.Errorf("failed to sign with ECDSA: %w", err)
	}

	// ECDSA signatures are R and S values, each the size of the curve
	// We concatenate them to form the signature
	keyBytes := e.KeySize
	sig := make([]byte, 2*keyBytes)
	r.FillBytes(sig[:keyBytes])
	s.FillBytes(sig[keyBytes:])

	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func (e *ecdsaSigningMethod) Verify(signingString string, signature string, key any) error {
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		// Support *ecdsa.PrivateKey for verification (extract public key)
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

	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	keyBytes := e.KeySize
	if len(sigBytes) != 2*keyBytes {
		return errors.New("ECDSA signature verification failed")
	}

	r := new(big.Int).SetBytes(sigBytes[:keyBytes])
	s := new(big.Int).SetBytes(sigBytes[keyBytes:])

	hasher := e.HashFunc.New()
	hasher.Write(stringToBytes(signingString))
	hashed := hasher.Sum(nil)

	valid := ecdsa.Verify(ecdsaKey, hashed, r, s)
	if !valid {
		return errors.New("ECDSA signature verification failed")
	}

	return nil
}

var (
	ecdsaES256 = &ecdsaSigningMethod{"ES256", crypto.SHA256, 32}
	ecdsaES384 = &ecdsaSigningMethod{"ES384", crypto.SHA384, 48}
	ecdsaES512 = &ecdsaSigningMethod{"ES512", crypto.SHA512, 66}
)
