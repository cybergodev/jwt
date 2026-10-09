package internal

import (
	"bytes"
	"crypto/rsa"
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

// Method defines the interface for JWT signing algorithms: the operations
// the token pipeline actually consumes. The hot paths sign via SignTo
// (encoding directly into the caller's buffer); Sign is the convenience
// primitive for direct use and tests, sizing its own buffer.
//
// Concrete implementations additionally expose Hash() crypto.Hash; it is
// intentionally not part of this contract because no pipeline path reads it.
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
}

// globalMethods holds registered signing methods.
// Populated exclusively in init(); read-only thereafter, so no mutex needed.
var globalMethods map[string]Method

func init() {
	// Populate read-only method registry (no further writes after init).
	globalMethods = map[string]Method{
		"HS256": hmacHS256,
		"HS384": hmacHS384,
		"HS512": hmacHS512,
		"RS256": rsaRS256,
		"RS384": rsaRS384,
		"RS512": rsaRS512,
		"PS256": rsaPS256,
		"PS384": rsaPS384,
		"PS512": rsaPS512,
		"ES256": ecdsaES256,
		"ES384": ecdsaES384,
		"ES512": ecdsaES512,
	}
}

// signingBufPool pools byte slices for signing string construction.
var signingBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 512)
		return &buf
	},
}

// encoderBuf pairs a pooled bytes.Buffer with a reusable json.Encoder.
// Sharing the encoder across calls eliminates the json.NewEncoder heap
// allocation (~80 bytes) per SignToken invocation.
type encoderBuf struct {
	buf *bytes.Buffer
	enc *json.Encoder
}

var encoderBufPool = sync.Pool{
	New: func() any {
		buf := bytes.NewBuffer(make([]byte, 0, 512))
		return &encoderBuf{
			buf: buf,
			enc: json.NewEncoder(buf),
		}
	},
}

// claimsBufPool pools the plain byte slices the JSONAppender path encodes into.
// A raw slice (rather than encoderBuf's bytes.Buffer) lets AppendJSON write
// straight into the pooled capacity: no Buffer.Write copy for any payload,
// and payloads that outgrow the initial capacity allocate once (append growth)
// instead of twice (append growth plus the buffer's own growth).
var claimsBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 512)
		return &buf
	},
}

// putClaimsBuf returns a claims buffer to the pool. Buffers grown past 4096
// bytes are dropped so one large token cannot inflate every pooled slot
// (mirrors signingJob.release's guard).
func putClaimsBuf(bufPtr *[]byte) {
	if cap(*bufPtr) <= 4096 {
		*bufPtr = (*bufPtr)[:0]
		claimsBufPool.Put(bufPtr)
	}
}

// JSONAppender is implemented by claims types that can append their JSON
// encoding directly to a byte slice (the built-in jwt.Claims does). Encoding
// into the caller's buffer skips both encoding/json's reflection walk and
// the marshal-then-copy pass its Encoder performs.
type JSONAppender interface {
	// AppendJSON appends the JSON encoding to dst and returns the extended
	// slice. The appended bytes must be exactly what json.Marshal would
	// produce for the claims value.
	AppendJSON(dst []byte) ([]byte, error)
}

// signingJob holds the pooled state shared by the SignToken entry points.
// Declared on the caller's stack so the shared prologue adds no allocation.
// Exactly one of eb (json.Encoder path) and claimsPtr (JSONAppender path) is
// set by beginSigning; release returns whichever it finds.
type signingJob struct {
	eb            *encoderBuf
	claimsPtr     *[]byte
	bufPtr        *[]byte
	signingString string
	sigDst        []byte
	sigOffset     int
}

// beginSigning is the prologue shared by SignToken and SignTokenHMAC: resolve
// the precomputed header, marshal the claims into a pooled buffer (JSONAppender
// claims encode directly into a pooled byte slice; everything else goes through
// a pooled json.Encoder), and build the signing string and signature
// destination in a pooled buffer via prepareSigning.
//
// On success the caller MUST call job.release() (usually deferred) — it owns
// the pooled entries from that point. On failure every pooled entry has
// already been returned and job is left zeroed.
func beginSigning(alg string, claims any, sigReserve int, job *signingJob) error {
	headerEncoded := precomputedHeaders[alg]
	if headerEncoded == "" {
		return fmt.Errorf("no precomputed header for algorithm: %s", alg)
	}

	var claimsJSON []byte
	if ja, ok := claims.(JSONAppender); ok {
		// Fast path: claims append their JSON directly into the pooled
		// slice's capacity — no reflection, no intermediate copy, no
		// bytes.Buffer round-trip.
		bufPtr := claimsBufPool.Get().(*[]byte)
		dst, err := ja.AppendJSON((*bufPtr)[:0])
		if err != nil {
			putClaimsBuf(bufPtr)
			return fmt.Errorf("failed to marshal claims: %w", err)
		}
		*bufPtr = dst // keep the (possibly grown) backing array for release
		job.claimsPtr = bufPtr
		claimsJSON = dst
	} else {
		eb := encoderBufPool.Get().(*encoderBuf)
		eb.buf.Reset()
		if err := eb.enc.Encode(claims); err != nil {
			encoderBufPool.Put(eb)
			return fmt.Errorf("failed to marshal claims: %w", err)
		}
		job.eb = eb
		claimsJSON = eb.buf.Bytes()
		// Trim trailing newline added by json.Encoder.Encode.
		if n := len(claimsJSON); n > 0 && claimsJSON[n-1] == '\n' {
			claimsJSON = claimsJSON[:n-1]
		}
	}

	job.bufPtr = signingBufPool.Get().(*[]byte)
	job.signingString, job.sigDst, job.sigOffset = prepareSigning(headerEncoded, claimsJSON, job.bufPtr, sigReserve)
	return nil
}

// release returns the job's pooled entries. Buffers grown past 4096 bytes are
// dropped instead of pooled so one large token cannot inflate every pooled slot.
func (job *signingJob) release() {
	if job.eb != nil {
		encoderBufPool.Put(job.eb)
	} else {
		putClaimsBuf(job.claimsPtr)
	}
	if cap(*job.bufPtr) <= 4096 {
		*job.bufPtr = (*job.bufPtr)[:0]
		signingBufPool.Put(job.bufPtr)
	}
}

// token builds the final token string. SAFETY: signingString aliases
// bufPtr's [0:signingStringLen) and sigDst is the region after the trailing
// '.', so they never overlap; both stay valid until release returns bufPtr
// to signingBufPool.
func (job *signingJob) token(sigLen int) string {
	return string((*job.bufPtr)[:job.sigOffset+sigLen])
}

// SignToken creates a signed JWT token string directly without allocating
// a Core struct or header map. Uses precomputed headers for all built-in algorithms.
// Encodes claims with a pooled JSON buffer and signs directly into the output buffer
// to minimize allocations.
func SignToken(alg string, claims any, method Method, key any) (string, error) {
	var job signingJob
	if err := beginSigning(alg, claims, signatureReserve(key), &job); err != nil {
		return "", err
	}
	defer job.release()

	sigLen, err := method.SignTo(job.sigDst, job.signingString, key)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return job.token(sigLen), nil
}

// SignTokenHMAC is a type-specialized variant of SignToken for HMAC algorithms.
// It accepts the HMAC key as []byte directly, avoiding the interface boxing that
// causes the key to escape to heap.
func SignTokenHMAC(alg string, claims any, method Method, key []byte) (string, error) {
	var job signingJob
	if err := beginSigning(alg, claims, defaultSigReserve, &job); err != nil {
		return "", err
	}
	defer job.release()

	// Type-assert to HMAC method for direct []byte key usage.
	hm, ok := method.(*hmacSigningMethod)
	if !ok {
		return "", fmt.Errorf("internal error: SignTokenHMAC called with non-HMAC method %T", method)
	}
	sigLen, err := hm.SignToHMAC(job.sigDst, job.signingString, key)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return job.token(sigLen), nil
}

// prepareSigning builds the "header.payload" signing string in bufPtr's pooled
// capacity and prepares the signature destination, returning:
//   - signingString: the header.payload portion, aliased to bufPtr's [0:signingStringLen)
//     via unsafe.String (valid until the caller returns bufPtr to the pool);
//   - sigDst: the slice (fullBuf[sigOffset:]) the caller passes verbatim to its
//     type-specialized SignTo/SignToHMAC — must not be re-derived by the caller;
//   - sigOffset: the byte offset where the signature begins, so the caller can
//     slice the final token as (*bufPtr)[:sigOffset+sigLen].
//
// The caller owns bufPtr and the deferred pool return; prepareSigning neither
// acquires nor returns pool entries. signingString and sigDst are separated by
// the '.' written at sigOffset-1, so they never overlap.
func prepareSigning(headerEncoded string, claimsJSON []byte, bufPtr *[]byte, sigReserve int) (signingString string, sigDst []byte, sigOffset int) {
	claimsEncodedLen := base64.RawURLEncoding.EncodedLen(len(claimsJSON))
	signingStringLen := len(headerEncoded) + 1 + claimsEncodedLen

	// Ensure capacity for signing string + separator + signature. sigReserve
	// is the worst-case base64 signature length for THIS key (see
	// signatureReserve): a fixed reserve undersized RSA keys above 4096 bits
	// and made Create fail with "signature buffer too small".
	needed := signingStringLen + 1 + sigReserve
	if cap(*bufPtr) < needed {
		*bufPtr = make([]byte, 0, needed+128)
	}

	signingStringBuf := (*bufPtr)[:signingStringLen]
	copy(signingStringBuf, stringToBytes(headerEncoded))
	signingStringBuf[len(headerEncoded)] = '.'
	base64.RawURLEncoding.Encode(signingStringBuf[len(headerEncoded)+1:], claimsJSON)

	signingString = unsafe.String(&signingStringBuf[0], len(signingStringBuf))

	fullBuf := (*bufPtr)[:cap(*bufPtr)]
	sigOffset = signingStringLen + 1
	fullBuf[sigOffset-1] = '.'
	return signingString, fullBuf[sigOffset:], sigOffset
}

// defaultSigReserve is the base64-encoded worst-case signature capacity
// reserved after the signing string. It covers HMAC (86), ECDSA (176), and
// RSA up to 4096 bits (684); larger RSA keys are sized from the key itself
// by signatureReserve.
const defaultSigReserve = 1024

// signatureReserve returns the base64-encoded worst-case signature length
// for key. The RSA modulus length is unbounded above the enforced 2048-bit
// minimum (an 8192-bit key yields a 1366-char signature), so RSA reserves
// capacity derived from the key; every other algorithm fits defaultSigReserve.
func signatureReserve(key any) int {
	// The N != nil guard mirrors rsaSignBuf: an empty key struct would panic
	// in Size() before validation rejects it.
	if k, ok := key.(*rsa.PrivateKey); ok && k != nil && k.N != nil {
		return base64.RawURLEncoding.EncodedLen(k.Size()) + 16
	}
	return defaultSigReserve
}

// GetInternalSigningMethod retrieves a signing method by algorithm name.
// All built-in methods are registered in init(), so this simply checks the registry.
func GetInternalSigningMethod(alg string) (Method, error) {
	if method := globalMethods[alg]; method != nil {
		return method, nil
	}
	return nil, fmt.Errorf("unsupported signing method: %s", alg)
}
