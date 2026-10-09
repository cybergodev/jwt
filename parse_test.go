package jwt

import (
	"errors"
	"testing"
	"time"
)

// newParseProc builds a processor with the shared test key and the given
// RejectRefreshAsAccess setting.
func newParseProc(t *testing.T, rejectRefresh bool) *Processor {
	t.Helper()
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.RejectRefreshAsAccess = rejectRefresh
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return p
}

// foreignSecretKey is a second strong HMAC key used to sign tokens that must
// fail signature verification.
const foreignSecretKey = "zA7*pQ4@wE9#rT2&uY5!iO8^bN1$cM6%xZ3+vK0-jH7~gD4$fS6%hJ3#kL9!"

// TestParse covers the error-only counterpart of Validate: round trip, the
// documented error conditions, and the RejectRefreshAsAccess opt-in.
func TestParse(t *testing.T) {
	p := newParseProc(t, false)
	defer func() { _ = p.Close() }() // best-effort cleanup

	token, err := p.Create(&Claims{UserID: "parse-user", Username: "test"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	claims, err := p.Parse(token)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if claims.UserID != "parse-user" {
		t.Errorf("claims.UserID = %q, want %q", claims.UserID, "parse-user")
	}

	if _, err := p.Parse(""); !errors.Is(err, ErrEmptyToken) {
		t.Errorf("empty token: errors.Is(err, ErrEmptyToken) = false, err = %v", err)
	}
	if _, err := p.Parse("invalid.token.format"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("malformed token: errors.Is(err, ErrInvalidToken) = false, err = %v", err)
	}

	// A token signed with a different key must fail verification.
	foreignCfg := DefaultConfig()
	foreignCfg.SecretKey = foreignSecretKey
	foreign, err := New(foreignCfg)
	if err != nil {
		t.Fatalf("New(foreign) error = %v", err)
	}
	defer func() { _ = foreign.Close() }() // best-effort cleanup
	foreignToken, err := foreign.Create(&Claims{UserID: "foreign", Username: "test"})
	if err != nil {
		t.Fatalf("foreign.Create() error = %v", err)
	}
	if _, err := p.Parse(foreignToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("wrong key: errors.Is(err, ErrInvalidToken) = false, err = %v", err)
	}

	// An expired token is rejected: issued under a clock two hours in the
	// past (exp = then + 15 min), verified against the system clock.
	pastCfg := DefaultConfig()
	pastCfg.SecretKey = testSecretKey
	pastCfg.Clock = FixedClock{T: time.Now().Add(-2 * time.Hour)}
	pastIssuer, err := New(pastCfg)
	if err != nil {
		t.Fatalf("New(past) error = %v", err)
	}
	defer func() { _ = pastIssuer.Close() }() // best-effort cleanup
	expired, err := pastIssuer.Create(&Claims{UserID: "expired", Username: "test"})
	if err != nil {
		t.Fatalf("pastIssuer.Create() error = %v", err)
	}
	if _, err := p.Parse(expired); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired: errors.Is(err, ErrTokenExpired) = false, err = %v", err)
	}

	// Revocation is enforced on the Parse path.
	revoked, err := p.Create(&Claims{UserID: "revoked", Username: "test"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := p.Revoke(revoked); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if _, err := p.Parse(revoked); !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("revoked: errors.Is(err, ErrTokenRevoked) = false, err = %v", err)
	}

	// Closed processor.
	closed := newParseProc(t, false)
	if err := closed.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := closed.Parse(token); !errors.Is(err, ErrProcessorClosed) {
		t.Errorf("closed: errors.Is(err, ErrProcessorClosed) = false, err = %v", err)
	}

	// RejectRefreshAsAccess applies to Parse exactly as it did to Validate.
	rejecting := newParseProc(t, true)
	defer func() { _ = rejecting.Close() }() // best-effort cleanup
	refresh, err := rejecting.CreateRefresh(&Claims{UserID: "rta-user", Username: "test"})
	if err != nil {
		t.Fatalf("CreateRefresh() error = %v", err)
	}
	if _, err := rejecting.Parse(refresh); !errors.Is(err, ErrTokenTypeMismatch) {
		t.Errorf("refresh-as-access: errors.Is(err, ErrTokenTypeMismatch) = false, err = %v", err)
	}
	// The default processor still accepts the same refresh token.
	if _, err := p.Parse(refresh); err != nil {
		t.Errorf("default processor should accept a refresh token, err = %v", err)
	}
}

// TestParseInto covers the custom-claims variant of Parse.
func TestParseInto(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = p.Close() }() // best-effort cleanup

	token, err := p.Create(&TestCustomClaims{UserID: "into-user", Email: "into@example.com", IsAdmin: true})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	result, err := p.ParseInto(token, &TestCustomClaims{})
	if err != nil {
		t.Fatalf("ParseInto() error = %v", err)
	}
	got := result.(*TestCustomClaims)
	if got.UserID != "into-user" || got.Email != "into@example.com" || !got.IsAdmin {
		t.Errorf("ParseInto() = %+v, want UserID/Email/IsAdmin preserved", got)
	}

	if _, err := p.ParseInto("", &TestCustomClaims{}); !errors.Is(err, ErrEmptyToken) {
		t.Errorf("empty token: errors.Is(err, ErrEmptyToken) = false, err = %v", err)
	}
	if _, err := p.ParseInto("invalid.token.format", &TestCustomClaims{}); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("malformed token: errors.Is(err, ErrInvalidToken) = false, err = %v", err)
	}
}

// TestValidateDelegatesToParse pins the deprecation contract: Validate and
// ValidateInto keep their signatures and behavior, with the bool always
// equivalent to err == nil and results identical to Parse/ParseInto.
func TestValidateDelegatesToParse(t *testing.T) {
	p := newParseProc(t, true)
	defer func() { _ = p.Close() }() // best-effort cleanup

	access, err := p.Create(&Claims{UserID: "delegate", Username: "test"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	refresh, err := p.CreateRefresh(&Claims{UserID: "delegate", Username: "test"})
	if err != nil {
		t.Fatalf("CreateRefresh() error = %v", err)
	}

	scenarios := []struct {
		name  string
		token string
	}{
		{"valid", access},
		{"refresh rejected", refresh},
		{"garbage", "not.a.jwt"},
		{"empty", ""},
	}

	for _, tc := range scenarios {
		vc, valid, verr := p.Validate(tc.token)
		pc, perr := p.Parse(tc.token)

		if valid != (verr == nil) {
			t.Errorf("%s: Validate valid=%v but verr=%v", tc.name, valid, verr)
		}
		if (verr == nil) != (perr == nil) {
			t.Errorf("%s: Validate err=%v but Parse err=%v", tc.name, verr, perr)
		}
		if verr == nil && vc.UserID != pc.UserID {
			t.Errorf("%s: Validate UserID=%q but Parse UserID=%q", tc.name, vc.UserID, pc.UserID)
		}
	}

	// ValidateInto mirrors ParseInto on the custom-claims path. The token is
	// issued as TestCustomClaims so its Validate contract (UserID + Email)
	// holds after unmarshaling.
	customToken, err := p.Create(&TestCustomClaims{UserID: "delegate", Email: "delegate@example.com"})
	if err != nil {
		t.Fatalf("Create(custom) error = %v", err)
	}
	_, valid, verr := p.ValidateInto(customToken, &TestCustomClaims{})
	_, perr := p.ParseInto(customToken, &TestCustomClaims{})
	if !valid || verr != nil {
		t.Errorf("ValidateInto(valid) = valid=%v err=%v", valid, verr)
	}
	if perr != nil {
		t.Errorf("ParseInto(valid) err = %v", perr)
	}
}
