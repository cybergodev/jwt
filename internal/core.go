package internal

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"unsafe"
)

// precomputedHeaders contains base64-encoded JWT headers for each algorithm.
// This avoids map allocation and JSON encoding for standard headers.
// Header format: {"typ":"JWT","alg":"<algorithm>"}
var precomputedHeaders = map[string]string{
	"HS256": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXIn0",
	"HS384": "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXIn0",
	"HS512": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXIn0",
	"RS256": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXIn0",
	"RS384": "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXIn0",
	"RS512": "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXIn0",
	"ES256": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXIn0",
	"ES384": "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXIn0",
	"ES512": "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXIn0",
}

// Method defines the interface for JWT signing algorithms.
type Method interface {
	// Alg returns the algorithm identifier (e.g., "HS256", "RS256").
	Alg() string

	// Sign creates a signature for the given signing string.
	Sign(signingString string, key any) (string, error)

	// Verify checks if the signature is valid for the given signing string.
	Verify(signingString string, signature string, key any) error

	// Hash returns the hash function used by this method.
	Hash() crypto.Hash
}

// methodRegistry holds registered signing methods.
type methodRegistry struct {
	mu      sync.RWMutex
	methods map[string]Method
}

var globalRegistry = &methodRegistry{
	methods: make(map[string]Method),
}

func init() {
	// Register built-in HMAC methods
	globalRegistry.register("HS256", hmacHS256)
	globalRegistry.register("HS384", hmacHS384)
	globalRegistry.register("HS512", hmacHS512)

	// Register built-in RSA methods
	globalRegistry.register("RS256", rsaRS256)
	globalRegistry.register("RS384", rsaRS384)
	globalRegistry.register("RS512", rsaRS512)

	// Register built-in ECDSA methods
	globalRegistry.register("ES256", ecdsaES256)
	globalRegistry.register("ES384", ecdsaES384)
	globalRegistry.register("ES512", ecdsaES512)
}

func (r *methodRegistry) register(alg string, method Method) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.methods[alg] = method
}

func (r *methodRegistry) get(alg string) Method {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.methods[alg]
}

// signingBufPool pools byte slices for signing string construction.
var signingBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 512)
		return &buf
	},
}

// SignToken creates a signed JWT token string directly without allocating
// a Core struct or header map. Uses precomputed headers for all built-in algorithms.
func SignToken(alg string, claims any, method Method, key any) (string, error) {
	headerEncoded := precomputedHeaders[alg]
	if headerEncoded == "" {
		return "", fmt.Errorf("no precomputed header for algorithm: %s", alg)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	claimsEncodedLen := base64.RawURLEncoding.EncodedLen(len(claimsJSON))
	signingStringLen := len(headerEncoded) + 1 + claimsEncodedLen

	bufPtr := signingBufPool.Get().(*[]byte)
	defer func() {
		if cap(*bufPtr) <= 2048 {
			*bufPtr = (*bufPtr)[:0]
			signingBufPool.Put(bufPtr)
		}
	}()

	if cap(*bufPtr) < signingStringLen {
		*bufPtr = make([]byte, 0, signingStringLen+128)
	}

	signingStringBuf := (*bufPtr)[:signingStringLen]
	copy(signingStringBuf, stringToBytes(headerEncoded))
	signingStringBuf[len(headerEncoded)] = '.'
	base64.RawURLEncoding.Encode(signingStringBuf[len(headerEncoded)+1:], claimsJSON)

	signingString := unsafe.String(&signingStringBuf[0], len(signingStringBuf))

	signature, err := method.Sign(signingString, key)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	// Assemble the final token directly into the pooled buffer.
	// Layout: [header.claims] + '.' + [signature]
	totalLen := signingStringLen + 1 + len(signature)

	// Grow buffer once if needed and copy signature in a single operation.
	if cap(*bufPtr) < totalLen {
		newBuf := make([]byte, totalLen)
		copy(newBuf, signingStringBuf)
		*bufPtr = newBuf
	}
	fullToken := (*bufPtr)[:totalLen]
	fullToken[signingStringLen] = '.'
	copy(fullToken[signingStringLen+1:], signature)

	// string([]byte) allocates a new copy — safe to return after buffer goes back to pool.
	return string(fullToken), nil
}

// GetInternalSigningMethod retrieves a signing method by algorithm name.
// All built-in methods are registered in init(), so this simply checks the registry.
func GetInternalSigningMethod(alg string) (Method, error) {
	if method := globalRegistry.get(alg); method != nil {
		return method, nil
	}
	return nil, fmt.Errorf("unsupported signing method: %s", alg)
}
