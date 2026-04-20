package internal

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
)

type rsaSigningMethod struct {
	Name     string
	HashFunc crypto.Hash
}

func (r *rsaSigningMethod) Alg() string {
	return r.Name
}

func (r *rsaSigningMethod) Hash() crypto.Hash {
	return r.HashFunc
}

func (r *rsaSigningMethod) Sign(signingString string, key any) (string, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("RSA key must be *rsa.PrivateKey, got %T", key)
	}
	if rsaKey == nil {
		return "", fmt.Errorf("RSA key cannot be nil")
	}

	if !r.HashFunc.Available() {
		return "", fmt.Errorf("hash function %v not available", r.HashFunc)
	}

	hasher := r.HashFunc.New()
	hasher.Write(stringToBytes(signingString))
	hashed := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, r.HashFunc, hashed)
	if err != nil {
		return "", fmt.Errorf("failed to sign with RSA: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(signature), nil
}

func (r *rsaSigningMethod) Verify(signingString string, signature string, key any) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		// Support *rsa.PrivateKey for verification (extract public key)
		privKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("RSA key must be *rsa.PublicKey or *rsa.PrivateKey, got %T", key)
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

	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Validate signature length matches RSA key size
	// RSA signature length must equal the modulus size in bytes
	expectedSigLen := rsaKey.Size()
	if len(sigBytes) != expectedSigLen {
		return errors.New("RSA signature verification failed")
	}

	hasher := r.HashFunc.New()
	hasher.Write(stringToBytes(signingString))
	hashed := hasher.Sum(nil)

	err = rsa.VerifyPKCS1v15(rsaKey, r.HashFunc, hashed, sigBytes)
	if err != nil {
		return errors.New("RSA signature verification failed")
	}

	return nil
}

var (
	rsaRS256 = &rsaSigningMethod{"RS256", crypto.SHA256}
	rsaRS384 = &rsaSigningMethod{"RS384", crypto.SHA384}
	rsaRS512 = &rsaSigningMethod{"RS512", crypto.SHA512}
)
