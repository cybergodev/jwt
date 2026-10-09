package jwt

import (
	"errors"
	"testing"
)

// TestRejectRefreshAsAccess covers the opt-in token-type enforcement: by
// default a refresh token still passes Validate (historical behavior); with
// RejectRefreshAsAccess it is rejected with ErrTokenTypeMismatch, while
// access tokens and the Refresh flow itself keep working.
func TestRejectRefreshAsAccess(t *testing.T) {
	newProc := func(t *testing.T, reject bool) *Processor {
		t.Helper()
		cfg := DefaultConfig()
		cfg.SecretKey = testSecretKey
		cfg.RejectRefreshAsAccess = reject
		p, err := New(cfg)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		return p
	}

	proc := newProc(t, false)
	defer func() { _ = proc.Close() }() // best-effort cleanup

	refresh, err := proc.CreateRefresh(&Claims{UserID: "rta-user", Username: "test"})
	if err != nil {
		t.Fatalf("CreateRefresh() error = %v", err)
	}

	if _, valid, err := proc.Validate(refresh); !valid || err != nil {
		t.Errorf("default: refresh token should pass Validate, valid=%v err=%v", valid, err)
	}

	rejecting := newProc(t, true)
	defer func() { _ = rejecting.Close() }() // best-effort cleanup

	_, valid, err := rejecting.Validate(refresh)
	if valid || err == nil {
		t.Fatal("RejectRefreshAsAccess: Validate should reject a refresh token")
	}
	if !errors.Is(err, ErrTokenTypeMismatch) {
		t.Errorf("errors.Is(err, ErrTokenTypeMismatch) = false, err = %v", err)
	}

	into := &Claims{}
	_, valid, err = rejecting.ValidateInto(refresh, into)
	if valid || err == nil {
		t.Fatal("RejectRefreshAsAccess: ValidateInto should reject a refresh token")
	}
	if !errors.Is(err, ErrTokenTypeMismatch) {
		t.Errorf("ValidateInto: errors.Is(err, ErrTokenTypeMismatch) = false, err = %v", err)
	}

	// Access tokens must still pass on the rejecting processor.
	access, err := rejecting.Create(&Claims{UserID: "rta-user", Username: "test"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, valid, err := rejecting.Validate(access); !valid || err != nil {
		t.Errorf("access token should pass, valid=%v err=%v", valid, err)
	}

	// The refresh flow itself is unaffected by the flag.
	if _, err := rejecting.Refresh(refresh); err != nil {
		t.Errorf("Refresh() should still accept its refresh token: %v", err)
	}
}
