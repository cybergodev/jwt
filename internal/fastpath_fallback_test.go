package internal

import (
	"encoding/base64"
	"testing"
)

// TestParseNestedAlgHeaderFallsBack guards the fast-path fallback: the
// cheap alg scan is not JSON-structure-aware, and a legal header whose
// nested object holds an "alg" key before the real one used to make parsing
// fail outright (ErrAlgorithmMismatch / unsupported method) instead of
// falling back to the slow path's full header decode.
func TestParseNestedAlgHeaderFallsBack(t *testing.T) {
	header := `{"info":{"alg":"FAKE"},"alg":"HS256"}` // legal JSON, real alg last
	headerSeg := base64.RawURLEncoding.EncodeToString([]byte(header))
	claimsSeg := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"nested-alg-user"}`))
	signingString := headerSeg + "." + claimsSeg

	key := []byte("fallback-test-key-0123456789abcdef")

	var sig [64]byte
	n, err := hmacHS256.SignToHMAC(sig[:], signingString, key)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	// SignToHMAC writes the base64-encoded signature; n is its length.
	token := signingString + "." + string(sig[:n])

	got := map[string]any{}
	core, err := ParseWithClaimsHMAC(token, &got, key, "HS256")
	if err != nil {
		t.Fatalf("ParseWithClaimsHMAC should fall back and succeed, got %v", err)
	}
	defer ReleaseCore(core)
	if !core.Valid {
		t.Fatal("token should be valid after slow-path fallback")
	}
	if got["sub"] != "nested-alg-user" {
		t.Fatalf("claims not decoded, got %v", got)
	}

	// The generic (keyFunc) entry point must fall back the same way.
	got2 := map[string]any{}
	core2, err := ParseWithClaims(token, &got2, func(*Core) (any, error) {
		return key, nil
	}, "HS256")
	if err != nil {
		t.Fatalf("ParseWithClaims should fall back and succeed, got %v", err)
	}
	defer ReleaseCore(core2)
	if !core2.Valid {
		t.Fatal("generic path: token should be valid after fallback")
	}
}
