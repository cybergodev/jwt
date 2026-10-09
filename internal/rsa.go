package internal

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
)

// rsaMethodBase holds the fields and hashing plumbing shared by the RSA
// (PKCS#1 v1.5) and RSA-PSS method implementations. Keeping the shared logic
// in one place ensures the two families cannot drift — the pre-dedup code
// carried the same signature-decode bug in both copies.
type rsaMethodBase struct {
	Name     string
	HashFunc crypto.Hash
	hashPool sync.Pool
}

func (r *rsaMethodBase) Alg() string {
	return r.Name
}

func (r *rsaMethodBase) Hash() crypto.Hash {
	return r.HashFunc
}

// beginHash borrows a pooled hasher, feeds it signingString, and returns the
// hasher together with the digest. The digest aliases the pooled sum buffer,
// so the caller MUST keep the hasher out of the pool (typically via
// `defer r.hashPool.Put(hb)`) until it is done reading the digest — returning
// it earlier would let another goroutine mutate the aliased bytes.
func (r *rsaMethodBase) beginHash(signingString string) (*hasherBuf, []byte) {
	hb := r.hashPool.Get().(*hasherBuf)
	hb.Reset()
	hb.Write(stringToBytes(signingString))
	// hb.sum is heap-resident (pooled entry), so Sum does not escape a stack buffer.
	return hb, hb.Sum(hb.sum[:0])
}

// resolveRSASignKey extracts the *rsa.PrivateKey required for signing.
// family names the algorithm family in error messages ("RSA" / "RSA-PSS").
// Nil pointers and nil moduli are rejected up front: an empty key struct
// would otherwise panic in Size()/BitLen().
func resolveRSASignKey(key any, family string) (*rsa.PrivateKey, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type: %s signing requires *rsa.PrivateKey", family)
	}
	if rsaKey == nil {
		return nil, fmt.Errorf("RSA key cannot be nil")
	}
	if rsaKey.N == nil {
		return nil, fmt.Errorf("RSA key has nil modulus")
	}
	return rsaKey, nil
}

// resolveRSAVerifyKey extracts the *rsa.PublicKey used for verification,
// accepting a private key (its embedded public part is used). family names
// the algorithm family in error messages. Nil pointers and nil moduli are
// rejected before any Size() call, which would otherwise panic.
func resolveRSAVerifyKey(key any, family string) (*rsa.PublicKey, error) {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		privKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid key type: %s verification requires *rsa.PublicKey or *rsa.PrivateKey", family)
		}
		if privKey == nil {
			return nil, fmt.Errorf("RSA key cannot be nil")
		}
		rsaKey = &privKey.PublicKey
	}

	if rsaKey == nil {
		return nil, fmt.Errorf("RSA key cannot be nil")
	}
	if rsaKey.N == nil {
		return nil, fmt.Errorf("RSA key has nil modulus")
	}
	return rsaKey, nil
}

// decodeRSASignature base64url-decodes signature and returns it only if its
// length matches the modulus exactly. Keys up to RSA-4096 (512 bytes) used to
// decode into a stack buffer; since the helper returns the slice (it must
// outlive this frame), a stack buffer would escape and be heap-copied anyway,
// so it allocates one exact-size buffer instead — a single allocation that is
// noise next to the RSA math (tens of µs per verify). The +2 bound covers
// base64 group rounding — EncodedLen(Size) decodes to at most Size+2 bytes —
// so a valid signature never trips it, and anything longer is rejected
// before any decoding.
func decodeRSASignature(signature string, rsaKey *rsa.PublicKey) ([]byte, error) {
	decodedLen := base64.RawURLEncoding.DecodedLen(len(signature))
	if decodedLen > rsaKey.Size()+2 {
		return nil, errors.New("signature verification failed")
	}
	sigBytes := make([]byte, decodedLen)
	n, err := base64.RawURLEncoding.Decode(sigBytes, stringToBytes(signature))
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}
	sigBytes = sigBytes[:n]
	if len(sigBytes) != rsaKey.Size() {
		return nil, errors.New("signature verification failed")
	}
	return sigBytes, nil
}

// rsaSignBuf sizes the base64 encode buffer from the actual key: the RSA
// modulus length is unbounded above the enforced 2048-bit minimum, so a
// fixed buffer sized for RSA-4096 would reject larger keys (an 8192-bit
// key needs 1366 base64 chars). Non-RSA keys keep the RSA-4096 fallback.
func rsaSignBuf(key any) []byte {
	size := 512 // RSA-4096 signature size in bytes
	if k, ok := key.(*rsa.PrivateKey); ok && k != nil && k.N != nil {
		size = k.Size()
	}
	return make([]byte, base64.RawURLEncoding.EncodedLen(size))
}

type rsaSigningMethod struct {
	rsaMethodBase
}

func newRSAMethod(name string, hash crypto.Hash) *rsaSigningMethod {
	return &rsaSigningMethod{
		rsaMethodBase: rsaMethodBase{
			Name:     name,
			HashFunc: hash,
			hashPool: sync.Pool{
				New: func() any { return &hasherBuf{Hash: hash.New()} },
			},
		},
	}
}

func (r *rsaSigningMethod) SignTo(dst []byte, signingString string, key any) (int, error) {
	rsaKey, err := resolveRSASignKey(key, "RSA")
	if err != nil {
		return 0, err
	}

	if !r.HashFunc.Available() {
		return 0, fmt.Errorf("hash function %v not available", r.HashFunc)
	}

	hb, hashed := r.beginHash(signingString)
	defer r.hashPool.Put(hb)

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
	buf := rsaSignBuf(key)
	n, err := r.SignTo(buf, signingString, key)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func (r *rsaSigningMethod) Verify(signingString string, signature string, key any) error {
	rsaKey, err := resolveRSAVerifyKey(key, "RSA")
	if err != nil {
		return err
	}

	if !r.HashFunc.Available() {
		return fmt.Errorf("hash function %v not available", r.HashFunc)
	}

	sigBytes, err := decodeRSASignature(signature, rsaKey)
	if err != nil {
		return err
	}

	hb, hashed := r.beginHash(signingString)
	defer r.hashPool.Put(hb)

	if rsa.VerifyPKCS1v15(rsaKey, r.HashFunc, hashed, sigBytes) != nil {
		return errors.New("signature verification failed")
	}

	return nil
}

var (
	rsaRS256 = newRSAMethod("RS256", crypto.SHA256)
	rsaRS384 = newRSAMethod("RS384", crypto.SHA384)
	rsaRS512 = newRSAMethod("RS512", crypto.SHA512)
)

type rsaPSSSigningMethod struct {
	rsaMethodBase
	opts rsa.PSSOptions
}

func (r *rsaPSSSigningMethod) SignTo(dst []byte, signingString string, key any) (int, error) {
	rsaKey, err := resolveRSASignKey(key, "RSA-PSS")
	if err != nil {
		return 0, err
	}

	if !r.HashFunc.Available() {
		return 0, fmt.Errorf("hash function %v not available", r.HashFunc)
	}

	hb, hashed := r.beginHash(signingString)
	defer r.hashPool.Put(hb)

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
	buf := rsaSignBuf(key)
	n, err := r.SignTo(buf, signingString, key)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func (r *rsaPSSSigningMethod) Verify(signingString string, signature string, key any) error {
	rsaKey, err := resolveRSAVerifyKey(key, "RSA-PSS")
	if err != nil {
		return err
	}

	if !r.HashFunc.Available() {
		return fmt.Errorf("hash function %v not available", r.HashFunc)
	}

	sigBytes, err := decodeRSASignature(signature, rsaKey)
	if err != nil {
		return err
	}

	hb, hashed := r.beginHash(signingString)
	defer r.hashPool.Put(hb)

	if rsa.VerifyPSS(rsaKey, r.HashFunc, hashed, sigBytes, &r.opts) != nil {
		return errors.New("signature verification failed")
	}

	return nil
}

func newRSSMethod(name string, hash crypto.Hash) *rsaPSSSigningMethod {
	return &rsaPSSSigningMethod{
		rsaMethodBase: rsaMethodBase{
			Name:     name,
			HashFunc: hash,
			hashPool: sync.Pool{
				New: func() any { return &hasherBuf{Hash: hash.New()} },
			},
		},
		opts: rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash},
	}
}

var (
	rsaPS256 = newRSSMethod("PS256", crypto.SHA256)
	rsaPS384 = newRSSMethod("PS384", crypto.SHA384)
	rsaPS512 = newRSSMethod("PS512", crypto.SHA512)
)
