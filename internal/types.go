package internal

// Core is the internal representation of a parsed JWT: its decoded header,
// claims, and signature, plus cached parse state consumed by the verification
// fast path. Cores are pooled — obtain one from a Parse* function and return it
// with ReleaseCore.
type Core struct {
	Header map[string]any
	Claims any
	// Signature is the raw third segment. Diagnostic only (tests/debugging);
	// no production path reads it.
	Signature string
	Valid     bool
	// Raw is the original token string. Diagnostic only (tests/debugging);
	// no production path reads it.
	Raw string
	// Alg caches the algorithm extracted during fast-path parsing so keyFunc
	// can read it without storing the string as an interface in Header (which
	// causes one heap allocation per parse for the string→any boxing).
	// Empty when the slow path (full header decode) was used.
	Alg string
}
