package jwt

import (
	"errors"
	"testing"
)

// nilRegisteredClaimsClaims is a deliberately broken CustomClaims
// implementation: GetRegisteredClaims returns nil, which every Processor path
// that dereferences the result must convert to a returned error.
type nilRegisteredClaimsClaims struct {
	RegisteredClaims
}

func (c *nilRegisteredClaimsClaims) GetRegisteredClaims() *RegisteredClaims { return nil }
func (c *nilRegisteredClaimsClaims) Validate() error                        { return nil }

// flakyRegisteredClaims returns nil on every even call, so the nil return
// surfaces at varying consumption points across an operation. Every
// GetRegisteredClaims consumption site routes through requireRegisteredClaims,
// so no interleaving may panic regardless of where the nil lands.
type flakyRegisteredClaims struct {
	RegisteredClaims
	calls int
}

func (c *flakyRegisteredClaims) GetRegisteredClaims() *RegisteredClaims {
	c.calls++
	if c.calls%2 == 0 {
		return nil
	}
	return &c.RegisteredClaims
}

func (c *flakyRegisteredClaims) Validate() error { return nil }

// mustNotPanic runs f, reporting a panic as a test error.
func mustNotPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: panicked instead of returning an error: %v", name, r)
		}
	}()
	f()
}

// TestNilProcessorNoPanic guards nil-receiver safety on the whole Processor
// surface: every method reports ErrProcessorClosed (IsClosed reports true)
// instead of dereferencing the nil receiver.
func TestNilProcessorNoPanic(t *testing.T) {
	var p *Processor

	cases := []struct {
		name string
		run  func() error
	}{
		{"Create", func() error { _, err := p.Create(&Claims{UserID: "u"}); return err }},
		{"CreateRefresh", func() error { _, err := p.CreateRefresh(&Claims{UserID: "u"}); return err }},
		{"Parse", func() error { _, err := p.Parse("a.b.c"); return err }},
		{"Validate", func() error { _, _, err := p.Validate("a.b.c"); return err }},
		{"Refresh", func() error { _, err := p.Refresh("a.b.c"); return err }},
		{"Revoke", func() error { return p.Revoke("a.b.c") }},
		{"IsRevoked", func() error { _, err := p.IsRevoked("a.b.c"); return err }},
		{"ParseUnverified", func() error { return p.ParseUnverified("a.b.c", &Claims{}) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got error
			mustNotPanic(t, c.name, func() { got = c.run() })
			if !errors.Is(got, ErrProcessorClosed) {
				t.Errorf("%s: want ErrProcessorClosed, got %v", c.name, got)
			}
		})
	}

	t.Run("ParseInto", func(t *testing.T) {
		mustNotPanic(t, "ParseInto", func() { _, _ = p.ParseInto("a.b.c", &Claims{}) })
	})
	t.Run("RefreshInto", func(t *testing.T) {
		mustNotPanic(t, "RefreshInto", func() { _, _ = p.RefreshInto("a.b.c", &Claims{}) })
	})
	t.Run("ValidateInto", func(t *testing.T) {
		mustNotPanic(t, "ValidateInto", func() { _, _, _ = p.ValidateInto("a.b.c", &Claims{}) })
	})
	t.Run("Close", func(t *testing.T) {
		mustNotPanic(t, "Close", func() {
			if err := p.Close(); !errors.Is(err, ErrProcessorClosed) {
				t.Errorf("Close: want ErrProcessorClosed, got %v", err)
			}
		})
	})
	t.Run("IsClosed", func(t *testing.T) {
		mustNotPanic(t, "IsClosed", func() {
			if !p.IsClosed() {
				t.Error("IsClosed on nil processor: want true")
			}
		})
	})
}

// TestNilRateLimiterNoPanic guards nil-receiver safety on RateLimiter: Allow
// and AllowN deny (fail-closed), Reset and Close are no-ops.
func TestNilRateLimiterNoPanic(t *testing.T) {
	var rl *RateLimiter

	mustNotPanic(t, "Allow", func() {
		if rl.Allow("key") {
			t.Error("Allow on nil limiter: want denial")
		}
	})
	mustNotPanic(t, "AllowN", func() {
		if rl.AllowN("key", 1) {
			t.Error("AllowN on nil limiter: want denial")
		}
	})
	mustNotPanic(t, "Reset", func() { rl.Reset("key") })
	mustNotPanic(t, "Close", func() { rl.Close() })

	// A typed-nil *RateLimiter injected through Config.RateLimiter reaches the
	// same guards via the Processor: the limiter interface is non-nil, so
	// checkRateLimit calls through to the nil receiver and must fail closed
	// (ErrRateLimitExceeded), not panic.
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.RateLimiter = rl
	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("New with typed-nil limiter: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	mustNotPanic(t, "Create via typed-nil limiter", func() {
		_, err := processor.Create(&Claims{UserID: "rate-limited"})
		if !errors.Is(err, ErrRateLimitExceeded) {
			t.Errorf("Create with nil limiter: want ErrRateLimitExceeded, got %v", err)
		}
	})
}

// TestTypedNilClaimsNoPanic guards the typed-nil seam: a (*Claims)(nil) boxed
// in a CustomClaims or any parameter passes every interface non-nil check,
// yet has a nil pointer receiver — and *Claims implements FastUnmarshaler, so
// the parse fast path would call methods on the nil receiver before
// encoding/json ever gets the chance to reject the nil destination with
// InvalidUnmarshalError. Every entry point must return an error instead.
func TestTypedNilClaimsNoPanic(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("newTestProcessor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	access, err := processor.Create(&Claims{UserID: "typed-nil"})
	if err != nil {
		t.Fatalf("setup Create failed: %v", err)
	}
	refresh, err := processor.CreateRefresh(&Claims{UserID: "typed-nil"})
	if err != nil {
		t.Fatalf("setup CreateRefresh failed: %v", err)
	}

	var typedNil *Claims
	// invalidClaims entries must return ErrInvalidClaims, matching the
	// Create-path behavior for the same input (validateCustomClaims).
	invalidClaims := []struct {
		name string
		run  func() error
	}{
		{"Create", func() error { _, err := processor.Create(typedNil); return err }},
		{"CreateRefresh", func() error { _, err := processor.CreateRefresh(typedNil); return err }},
		{"ParseInto", func() error { _, err := processor.ParseInto(access, typedNil); return err }},
		{"ValidateInto", func() error { _, _, err := processor.ValidateInto(access, typedNil); return err }},
		{"RefreshInto", func() error { _, err := processor.RefreshInto(refresh, typedNil); return err }},
	}
	for _, tc := range invalidClaims {
		t.Run(tc.name, func(t *testing.T) {
			var got error
			mustNotPanic(t, tc.name, func() { got = tc.run() })
			if !errors.Is(got, ErrInvalidClaims) {
				t.Errorf("%s: want ErrInvalidClaims, got %v", tc.name, got)
			}
		})
	}

	// ParseUnverified takes any, so it rejects the nil destination lower in
	// the stack (encoding/json's InvalidUnmarshalError) — an error, not a panic.
	t.Run("ParseUnverified", func(t *testing.T) {
		var got error
		mustNotPanic(t, "ParseUnverified", func() { got = processor.ParseUnverified(access, typedNil) })
		if got == nil {
			t.Error("ParseUnverified with typed-nil claims: want an error")
		}
	})

	// A typed-nil custom type WITHOUT FastUnmarshaler never reaches a method
	// call: encoding/json rejects the nil destination directly.
	var typedNilCustom *TestCustomClaims
	customCases := []struct {
		name string
		run  func() error
	}{
		{"ParseInto custom", func() error { _, err := processor.ParseInto(access, typedNilCustom); return err }},
		{"RefreshInto custom", func() error { _, err := processor.RefreshInto(refresh, typedNilCustom); return err }},
		{"ParseUnverified custom", func() error { return processor.ParseUnverified(access, typedNilCustom) }},
	}
	for _, tc := range customCases {
		t.Run(tc.name, func(t *testing.T) {
			var got error
			mustNotPanic(t, tc.name, func() { got = tc.run() })
			if got == nil {
				t.Errorf("%s with typed-nil custom claims: want an error", tc.name)
			}
		})
	}
}

// TestNilGetRegisteredClaimsNoPanic guards the requireRegisteredClaims choke
// points: a CustomClaims implementation whose GetRegisteredClaims returns nil
// must surface ErrInvalidClaims from every entry point that consumes custom
// claims, never a nil-pointer panic.
func TestNilGetRegisteredClaimsNoPanic(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("newTestProcessor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	// A real, signed token so the nil-rc claims actually reach the field
	// consumption steps after a successful parse.
	token, err := processor.CreateRefresh(&Claims{UserID: "user123"})
	if err != nil {
		t.Fatalf("setup CreateRefresh failed: %v", err)
	}

	c := &nilRegisteredClaimsClaims{}
	cases := []struct {
		name string
		run  func() error
	}{
		{"Create", func() error { _, err := processor.Create(c); return err }},
		{"CreateRefresh", func() error { _, err := processor.CreateRefresh(c); return err }},
		{"ParseInto", func() error { _, err := processor.ParseInto(token, c); return err }},
		{"RefreshInto", func() error { _, err := processor.RefreshInto(token, c); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got error
			mustNotPanic(t, tc.name, func() { got = tc.run() })
			if !errors.Is(got, ErrInvalidClaims) {
				t.Errorf("%s: want ErrInvalidClaims, got %v", tc.name, got)
			}
		})
	}

	// The flaky variant must never panic no matter which consumption site the
	// nil return lands on; the error is still ErrInvalidClaims because a valid
	// token passes every other check.
	t.Run("flaky", func(t *testing.T) {
		flaky := func(name string, run func() error) {
			t.Run(name, func(t *testing.T) {
				var got error
				mustNotPanic(t, name, func() { got = run() })
				if !errors.Is(got, ErrInvalidClaims) {
					t.Errorf("%s: want ErrInvalidClaims, got %v", name, got)
				}
			})
		}
		flaky("Create", func() error { _, err := processor.Create(&flakyRegisteredClaims{}); return err })
		flaky("CreateRefresh", func() error { _, err := processor.CreateRefresh(&flakyRegisteredClaims{}); return err })
		flaky("ParseInto", func() error { _, err := processor.ParseInto(token, &flakyRegisteredClaims{}); return err })
		flaky("RefreshInto", func() error { _, err := processor.RefreshInto(token, &flakyRegisteredClaims{}); return err })
	})
}
