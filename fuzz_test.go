package jwt_test

import (
	"testing"

	"github.com/cybergodev/jwt"
)

// Fuzz targets for the public API. Token strings are attacker-controlled, so
// every entry point that accepts one must reject malformed input with an error
// rather than panicking. The fuzzer detects panics automatically.
//
// Run a long session with, e.g.:
//
//	go test . -run=^$ -fuzz=FuzzValidate -fuzztime=30s

// newFuzzProcessor builds a Processor with a fixed strong HMAC key for fuzzing.
func newFuzzProcessor(tb testing.TB) *jwt.Processor {
	tb.Helper()
	cfg := jwt.DefaultConfig()
	// High-entropy key that passes IsWeakKey (mixed classes, no weak substrings).
	cfg.SecretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"
	p, err := jwt.New(cfg)
	if err != nil {
		tb.Fatalf("failed to create processor: %v", err)
	}
	return p
}

// FuzzParseUnverified verifies the unverified parse path never panics on
// arbitrary input. Signature verification is intentionally skipped here, so the
// fuzzer exercises pure decoding/header handling.
func FuzzParseUnverified(f *testing.F) {
	p := newFuzzProcessor(f)
	defer func() { _ = p.Close() }() // best-effort cleanup

	for _, s := range []string{"", "a.b.c", "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidTEifQ.sig"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		var c jwt.Claims
		_ = p.ParseUnverified(token, &c) // must not panic
	})
}

// FuzzValidate drives the full validated path (parse, signature verify,
// registered-claims checks, blacklist, claims validation) with arbitrary input.
// It must never panic.
func FuzzValidate(f *testing.F) {
	p := newFuzzProcessor(f)
	defer func() { _ = p.Close() }() // best-effort cleanup

	for _, s := range []string{"", "a.b.c", "not.a.token", "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidTEifQ.sig"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		_, _, _ = p.Validate(token) // must not panic
	})
}

// FuzzRevoke verifies the revocation path (signature verify + jti extraction +
// blacklist insert) never panics on arbitrary input.
func FuzzRevoke(f *testing.F) {
	p := newFuzzProcessor(f)
	defer func() { _ = p.Close() }() // best-effort cleanup

	for _, s := range []string{"", "a.b.c", "garbage"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		_ = p.Revoke(token) // must not panic
	})
}
