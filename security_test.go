package jwt

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSecurityAlgorithmConfusion(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"none algorithm", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoidGVzdCJ9."},
		{"empty algorithm", "eyJhbGciOiIiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyX2lkIjoidGVzdCJ9.invalid"},
		{"weak algorithm", "eyJhbGciOiJIUzEiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyX2lkIjoidGVzdCJ9.invalid"},
	}

	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, valid, err := processor.Validate(tt.token)
			if valid || err == nil {
				t.Errorf("Should reject %s token", tt.name)
			}
		})
	}
}

func TestSecurityWeakKeys(t *testing.T) {
	tests := []struct {
		name string
		key  string
		weak bool
	}{
		// Weak keys
		{"common password", "password", true},
		{"too short", "short", true},
		{"empty", "", true},
		{"all same char", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true},
		{"sequential numbers", "12345678901234567890123456789012", true},
		{"all zeros", "00000000000000000000000000000000", true},
		{"all ones", "11111111111111111111111111111111", true},
		{"repeating pattern", "passwordpasswordpasswordpassword", true},
		{"keyboard pattern qwerty", "qwertyuiopasdfghjklzxcvbnm123456", true},
		{"keyboard pattern asdf", "asdfghjklqwertyuiopzxcvbnm123456", true},
		{"keyboard pattern numeric", "1234567890qwertyuiopasdfghjklzxc", true},
		{"repeating ab", "abababababababababababababababab", true},
		{"repeating 123", "123123123123123123123123123123123", true},
		{"common word padded", "secretsecretsecretsecretsecretsecret", true},
		{"alphabetical", "abcdefghijklmnopqrstuvwxyz123456", true},

		// Strong keys
		{"mixed special chars", "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!", false},
		{"strong with year", "Str0ng!S3cr3t#K3y$W1th%Suff1c13nt&Entr0py*2024", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newTestProcessor(tt.key)
			if tt.weak && err == nil {
				t.Errorf("Should reject weak key: %s", tt.name)
			}
			if !tt.weak && err != nil {
				t.Errorf("Should accept strong key %s: %v", tt.name, err)
			}
		})
	}
}

func TestSecurityMaliciousInput(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	tests := []struct {
		name      string
		pattern   string
		wantError bool
	}{
		// Injection patterns — should be rejected
		{"XSS script tag", "<script>alert('xss')</script>", true},
		{"XSS script tag uppercase", "<SCRIPT>alert('xss')</SCRIPT>", true},
		{"XSS script tag mixed case", "<ScRiPt>alert(1)</sCrIpT>", true},
		{"JavaScript URI", "javascript:alert(1)", true},
		{"JavaScript URI uppercase", "JavaScript:alert(1)", true},
		{"Event handler attribute", "onerror=alert(1)", true},
		{"Event handler uppercase", "OnError=alert(1)", true},
		{"Data URI script", "data:text/html,<script>alert(1)</script>", true},
		{"eval call", "eval('alert(1)')", true},
		{"Path traversal", "../../../etc/passwd", true},
		{"SQL injection", "1=1 union select password", true},
		{"File URI", "file:///etc/passwd", true},
		{"File URI uppercase", "FILE:///etc/passwd", true},
		{"VBScript", "vbscript:msgbox(1)", true},
		{"Null byte", "test\x00null", true},
		{"Too long field", strings.Repeat("a", 1000), true},

		// Acceptable patterns — should be allowed
		{"Email address", "user@example.com", false},
		{"HTTPS URL", "https://example.com/profile", false},
		{"Name with apostrophe", "John O'Brien", false},
		// Boundary: "javascript" without the colon is a plain word; the
		// pattern only matches with its full "javascript:" length, and a
		// value shorter than that at the match position must pass.
		{"javascript without colon", "javascript", false},
		// Boundary: exactly maxStringLength (256) is allowed; 257 is not
		// (covered by "Too long field" above at 1000).
		{"exactly max length", strings.Repeat("a", 256), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := Claims{UserID: "user123", Username: tt.pattern}
			_, err := processor.Create(&claims)
			if tt.wantError && err == nil {
				t.Errorf("Should reject: %s", tt.name)
			}
			if !tt.wantError && err != nil {
				t.Errorf("Should accept %s: %v", tt.name, err)
			}
		})
	}

	// CreateRefresh should also reject dangerous patterns
	claims := &Claims{UserID: "<script>alert('xss')</script>", Username: "test"}
	if _, err := processor.CreateRefresh(claims); err == nil {
		t.Error("CreateRefresh should reject dangerous patterns")
	}
}

func TestSecurityDoSProtection(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	tests := []struct {
		name   string
		claims Claims
	}{
		{
			"too many permissions",
			Claims{UserID: "test", Username: "test", Permissions: func() []string {
				p := make([]string, 200)
				for i := range p {
					p[i] = fmt.Sprintf("perm%d", i)
				}
				return p
			}()},
		},
		{
			"too many extra fields",
			Claims{UserID: "test", Username: "test", Extra: func() map[string]any {
				e := make(map[string]any)
				for i := 0; i < 100; i++ {
					e[fmt.Sprintf("field%d", i)] = "value"
				}
				return e
			}()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := processor.Create(&tt.claims); err == nil {
				t.Errorf("Should reject: %s", tt.name)
			}
		})
	}

	// Extremely long token should be rejected
	longToken := strings.Repeat("a", 200000) + ".b.c"
	_, valid, err := processor.Validate(longToken)
	if valid || err == nil {
		t.Error("Should reject extremely long tokens")
	}
}

func TestSecurityTokenValidation(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	tests := []struct {
		name  string
		token string
	}{
		{"null bytes", "token\x00with\x00nulls"},
		{"control chars", "token\x01with\x02control\x03chars"},
		{"very long", strings.Repeat("a", 20000)},
		{"XSS in token", "<script>alert('xss')</script>.payload.sig"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, valid, err := processor.Validate(tt.token)
			if valid || err == nil {
				t.Errorf("Should reject: %s", tt.name)
			}
		})
	}
}

// TestSecurityNilClaimsNoPanic verifies that nil claims (a nil interface or a
// typed-nil *Claims) never cause a panic on the public API — they must surface
// as a returned error. Regression guard for SEC-003 (Panic Protection).
func TestSecurityNilClaimsNoPanic(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	// A real, signed token so the nil-claims argument actually reaches the
	// decoding step (rather than being rejected as a malformed token).
	validToken, err := processor.Create(&Claims{UserID: "user123"})
	if err != nil {
		t.Fatalf("setup Create failed: %v", err)
	}

	var nilClaims *Claims         // typed-nil
	var nilInterface CustomClaims // nil interface

	// run asserts f returns a non-nil error and does not panic.
	run := func(t *testing.T, name string, f func() error) {
		t.Helper()
		var got error
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panicked instead of returning an error: %v", name, r)
				}
			}()
			got = f()
		}()
		if got == nil {
			t.Errorf("%s: expected an error for nil claims, got nil", name)
		}
	}

	cases := []struct {
		name   string
		action func() error
	}{
		{"Create(nil interface)", func() error { _, e := processor.Create(nil); return e }},
		{"CreateRefresh(nil interface)", func() error { _, e := processor.CreateRefresh(nil); return e }},
		{"Create(typed-nil *Claims)", func() error { _, e := processor.Create(nilClaims); return e }},
		{"CreateRefresh(typed-nil *Claims)", func() error { _, e := processor.CreateRefresh(nilClaims); return e }},
		{"ValidateInto(nil interface)", func() error { _, _, e := processor.ValidateInto(validToken, nilInterface); return e }},
		{"RefreshInto(nil interface)", func() error { _, e := processor.RefreshInto(validToken, nilInterface); return e }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { run(t, c.name, c.action) })
	}

	// Create/CreateRefresh nil cases should be identifiable via ErrInvalidClaims.
	if _, e := processor.Create(nil); !errors.Is(e, ErrInvalidClaims) {
		t.Errorf("Create(nil) error should wrap ErrInvalidClaims, got %v", e)
	}
	if _, e := processor.Create(nilClaims); !errors.Is(e, ErrInvalidClaims) {
		t.Errorf("Create(typed-nil *Claims) error should wrap ErrInvalidClaims, got %v", e)
	}
}
