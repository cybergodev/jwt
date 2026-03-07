package internal

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
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

// isStandardHeader checks if the header is a standard JWT header with only typ and alg fields.
// Returns the precomputed base64-encoded header if it matches, empty string otherwise.
func isStandardHeader(header map[string]any, alg string) string {
	if len(header) != 2 {
		return ""
	}
	typ, hasTyp := header["typ"].(string)
	if !hasTyp || typ != "JWT" {
		return ""
	}
	headerAlg, hasAlg := header["alg"].(string)
	if !hasAlg || headerAlg != alg {
		return ""
	}
	return precomputedHeaders[alg]
}

// signingBufPool pools byte slices for signing string construction.
var signingBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 512)
		return &buf
	},
}

func SignedString(header map[string]any, claims any, method Method, key any) (string, error) {
	alg := method.Alg()

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	claimsEncodedLen := base64.RawURLEncoding.EncodedLen(len(claimsJSON))

	var signingStringLen int
	var headerBytes []byte
	var isPrecomputed bool

	// Check if we can use precomputed header (already base64 encoded)
	if encoded := isStandardHeader(header, alg); encoded != "" {
		headerBytes = stringToBytes(encoded)
		signingStringLen = len(encoded) + 1 + claimsEncodedLen
		isPrecomputed = true
	} else {
		// Fall back to encoding the header
		headerJSON, err := json.Marshal(header)
		if err != nil {
			return "", fmt.Errorf("failed to marshal header: %w", err)
		}
		headerBytes = headerJSON
		headerEncodedLen := base64.RawURLEncoding.EncodedLen(len(headerJSON))
		signingStringLen = headerEncodedLen + 1 + claimsEncodedLen
	}

	// Use buffer pool for all cases
	bufPtr := signingBufPool.Get().(*[]byte)
	defer func() {
		if cap(*bufPtr) <= 2048 {
			*bufPtr = (*bufPtr)[:0]
			signingBufPool.Put(bufPtr)
		}
	}()

	if cap(*bufPtr) < signingStringLen {
		*bufPtr = make([]byte, 0, signingStringLen)
	}

	signingStringBuf := (*bufPtr)[:signingStringLen]

	if isPrecomputed {
		// Header is already base64 encoded, just copy it
		copy(signingStringBuf, headerBytes)
		signingStringBuf[len(headerBytes)] = '.'
		base64.RawURLEncoding.Encode(signingStringBuf[len(headerBytes)+1:], claimsJSON)
	} else {
		// Encode header to base64
		base64.RawURLEncoding.Encode(signingStringBuf, headerBytes)
		headerEncodedLen := base64.RawURLEncoding.EncodedLen(len(headerBytes))
		signingStringBuf[headerEncodedLen] = '.'
		base64.RawURLEncoding.Encode(signingStringBuf[headerEncodedLen+1:], claimsJSON)
	}

	// Use unsafe string for internal Sign call
	signingString := unsafe.String(&signingStringBuf[0], len(signingStringBuf))

	signature, err := method.Sign(signingString, key)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	// Use strings.Builder for efficient string concatenation
	var builder strings.Builder
	builder.Grow(signingStringLen + 1 + len(signature))
	builder.Write(signingStringBuf)
	builder.WriteByte('.')
	builder.WriteString(signature)

	return builder.String(), nil
}

// GetInternalSigningMethod retrieves a signing method by algorithm name.
// All built-in methods are registered in init(), so this simply checks the registry.
func GetInternalSigningMethod(alg string) (Method, error) {
	if method := globalRegistry.get(alg); method != nil {
		return method, nil
	}
	return nil, fmt.Errorf("unsupported signing method: %s", alg)
}
