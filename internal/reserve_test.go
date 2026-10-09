package internal

import (
	"crypto/rsa"
	"math/big"
	"testing"
)

// TestSignatureReserveByRSAKeySize guards the boundary fix: RSA signature
// reserves must scale with the modulus, not assume 4096 bits. An 8192-bit
// key needs a 1366-char base64 signature, which exceeds the old fixed 1024
// reserve and made the first Create fail with "signature buffer too small"
// (later calls could succeed or fail depending on pooled buffer history).
func TestSignatureReserveByRSAKeySize(t *testing.T) {
	if got := signatureReserve(nil); got != defaultSigReserve {
		t.Fatalf("signatureReserve(nil) = %d, want %d", got, defaultSigReserve)
	}

	// Synthetic key: only N's bit length matters for Size()/reserve math.
	n := new(big.Int).Lsh(big.NewInt(1), 8191) // 8192-bit modulus
	k := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: 65537}}
	got := signatureReserve(k)
	want := base64RawURLEncodedLen(1024) + 16
	if got != want {
		t.Fatalf("signatureReserve(8192-bit RSA) = %d, want %d", got, want)
	}
	if got <= 1024 {
		t.Fatal("8192-bit reserve must exceed the old fixed 1024")
	}
}

// TestPrepareSigningReservesSignatureSpace verifies the pooled buffer is
// grown for the requested reserve so SignTo's destination never comes up
// short on the first (fresh-buffer) call.
func TestPrepareSigningReservesSignatureSpace(t *testing.T) {
	const reserve = 1382 // 8192-bit RSA worst case
	buf := make([]byte, 0, 64)
	bufPtr := &buf

	signingString, sigDst, sigOffset := prepareSigning("h", []byte("c"), bufPtr, reserve)

	if len(sigDst) < reserve {
		t.Fatalf("sigDst len = %d, want >= %d", len(sigDst), reserve)
	}
	if len(signingString) == 0 {
		t.Fatal("signingString must be non-empty")
	}

	// Simulate SignTo writing a full-size signature, then build the token
	// slice exactly as the SignToken entry points do.
	for i := range sigDst[:reserve] {
		sigDst[i] = 'A'
	}
	token := string((*bufPtr)[:sigOffset+reserve])
	if len(token) == 0 {
		t.Fatal("token slice must be non-empty")
	}
}

// base64RawURLEncodedLen mirrors base64.RawURLEncoding.EncodedLen without
// importing encoding/base64 here just for one assertion.
func base64RawURLEncodedLen(n int) int {
	return (n*8 + 5) / 6
}
