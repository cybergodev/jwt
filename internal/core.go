package internal

import (
	"bytes"
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
	"PS256": "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXIn0",
	"PS384": "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXIn0",
	"PS512": "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXIn0",
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

	// SignTo writes the base64-encoded signature to dst and returns bytes written.
	// Avoids intermediate string allocation by encoding directly into the caller's buffer.
	SignTo(dst []byte, signingString string, key any) (int, error)

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

	// Register built-in RSA-PSS methods
	globalRegistry.register("PS256", rsaPS256)
	globalRegistry.register("PS384", rsaPS384)
	globalRegistry.register("PS512", rsaPS512)

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

// jsonEncoderPool pools bytes.Buffer for JSON encoding to avoid
// the internal allocation in json.Marshal's output copy.
var jsonEncoderPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(make([]byte, 0, 512))
	},
}

// SignToken creates a signed JWT token string directly without allocating
// a Core struct or header map. Uses precomputed headers for all built-in algorithms.
// Encodes claims with a pooled JSON buffer and signs directly into the output buffer
// to minimize allocations.
func SignToken(alg string, claims any, method Method, key any) (string, error) {
	headerEncoded := precomputedHeaders[alg]
	if headerEncoded == "" {
		return "", fmt.Errorf("no precomputed header for algorithm: %s", alg)
	}

	// Marshal claims using pooled JSON buffer to avoid json.Marshal's output copy.
	jsonBuf := jsonEncoderPool.Get().(*bytes.Buffer)
	jsonBuf.Reset()
	if err := json.NewEncoder(jsonBuf).Encode(claims); err != nil {
		jsonEncoderPool.Put(jsonBuf)
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	claimsJSON := jsonBuf.Bytes()
	// Trim trailing newline added by json.Encoder.Encode
	if n := len(claimsJSON); n > 0 && claimsJSON[n-1] == '\n' {
		claimsJSON = claimsJSON[:n-1]
	}

	claimsEncodedLen := base64.RawURLEncoding.EncodedLen(len(claimsJSON))
	signingStringLen := len(headerEncoded) + 1 + claimsEncodedLen

	bufPtr := signingBufPool.Get().(*[]byte)
	defer func() {
		jsonEncoderPool.Put(jsonBuf)
		if cap(*bufPtr) <= 4096 {
			*bufPtr = (*bufPtr)[:0]
			signingBufPool.Put(bufPtr)
		}
	}()

	// Ensure capacity for signing string + separator + signature.
	// 1024 bytes covers all practical signature sizes (HS512: 86, RS4096: 684, ES512: 176).
	needed := signingStringLen + 1 + 1024
	if cap(*bufPtr) < needed {
		*bufPtr = make([]byte, 0, needed+128)
	}

	// Build signing string in buffer.
	signingStringBuf := (*bufPtr)[:signingStringLen]
	copy(signingStringBuf, stringToBytes(headerEncoded))
	signingStringBuf[len(headerEncoded)] = '.'
	base64.RawURLEncoding.Encode(signingStringBuf[len(headerEncoded)+1:], claimsJSON)

	// SAFETY: signingString references bufPtr's pooled memory, which is valid
	// until the deferred cleanup returns it to signingBufPool. The underlying
	// bytes are never modified after this point — SignTo reads the string and
	// writes to a separate region of the same buffer.
	signingString := unsafe.String(&signingStringBuf[0], len(signingStringBuf))

	// Sign directly into buffer, avoiding intermediate base64 string allocation.
	fullBuf := (*bufPtr)[:cap(*bufPtr)]
	sigOffset := signingStringLen + 1
	fullBuf[sigOffset-1] = '.'

	sigLen, err := method.SignTo(fullBuf[sigOffset:], signingString, key)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return string(fullBuf[:sigOffset+sigLen]), nil
}

// GetInternalSigningMethod retrieves a signing method by algorithm name.
// All built-in methods are registered in init(), so this simply checks the registry.
func GetInternalSigningMethod(alg string) (Method, error) {
	if method := globalRegistry.get(alg); method != nil {
		return method, nil
	}
	return nil, fmt.Errorf("unsupported signing method: %s", alg)
}
