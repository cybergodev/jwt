package jwt

import (
	"errors"
	"testing"
)

// TestValidateAlgorithmMismatchSentinel locks the documented error contract:
// the verify paths must return an error matching both ErrInvalidToken and
// ErrAlgorithmMismatch via errors.Is.
//
// Regression guard: the parse layer returns the internal sentinel, and the
// processor used to wrap it with %v, which dropped it from the error chain —
// errors.Is(err, ErrAlgorithmMismatch) was always false despite the godoc
// promising that sentinel on Validate/ValidateInto/Refresh/RefreshInto.
func TestValidateAlgorithmMismatchSentinel(t *testing.T) {
	proc256, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("failed to create HS256 processor: %v", err)
	}
	defer func() { _ = proc256.Close() }() // best-effort cleanup

	token, err := proc256.Create(&Claims{UserID: "alg-mismatch", Username: "test"})
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.SigningMethod = SigningMethodHS384
	proc384, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create HS384 processor: %v", err)
	}
	defer func() { _ = proc384.Close() }() // best-effort cleanup

	_, _, err = proc384.Validate(token)
	if err == nil {
		t.Fatal("Validate should fail on algorithm mismatch")
	}
	if !errors.Is(err, ErrAlgorithmMismatch) {
		t.Errorf("Validate: errors.Is(err, ErrAlgorithmMismatch) = false, err = %v", err)
	}
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Validate: errors.Is(err, ErrInvalidToken) = false, err = %v", err)
	}

	_, _, err = proc384.ValidateInto(token, &Claims{})
	if err == nil {
		t.Fatal("ValidateInto should fail on algorithm mismatch")
	}
	if !errors.Is(err, ErrAlgorithmMismatch) {
		t.Errorf("ValidateInto: errors.Is(err, ErrAlgorithmMismatch) = false, err = %v", err)
	}

	_, err = proc384.Refresh(token)
	if err == nil {
		t.Fatal("Refresh should fail on algorithm mismatch")
	}
	if !errors.Is(err, ErrAlgorithmMismatch) {
		t.Errorf("Refresh: errors.Is(err, ErrAlgorithmMismatch) = false, err = %v", err)
	}
}
