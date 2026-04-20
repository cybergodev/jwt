package jwt

import (
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
	defer processor.Close()

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
		name  string
		key   string
		weak  bool
	}{
		// Weak keys
		{"common password", "password", true},
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

func TestSecurityInputValidation(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	tests := []struct {
		name   string
		claims Claims
	}{
		{"XSS script tag", Claims{UserID: "<script>alert('xss')</script>", Username: "test"}},
		{"JavaScript injection", Claims{UserID: "test", Username: "javascript:alert(1)"}},
		{"Too long field", Claims{UserID: "test", Username: strings.Repeat("a", 1000)}},
		{"Null byte", Claims{UserID: "test\x00null", Username: "test"}},
		{"Path traversal", Claims{UserID: "../../../etc/passwd", Username: "test"}},
		{"Data URI", Claims{UserID: "data:text/html,<script>", Username: "test"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := processor.Create(&tt.claims)
			if err == nil {
				t.Errorf("Should reject malicious claims: %s", tt.name)
			}
		})
	}
}

func TestSecurityDoSProtection(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

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
	longToken := strings.Repeat("a", 20000) + ".b.c"
	_, valid, err := processor.Validate(longToken)
	if valid || err == nil {
		t.Error("Should reject extremely long tokens")
	}
}

func TestSecurityInjectionPatterns(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

	tests := []struct {
		name      string
		pattern   string
		wantError bool
	}{
		// Critical patterns that should be blocked
		{"XSS script", "<script>alert('xss')</script>", true},
		{"JavaScript URI", "javascript:alert(1)", true},
		{"Data URI script", "data:text/html,<script>alert(1)</script>", true},
		{"eval call", "eval('alert(1)')", true},
		{"Path traversal", "../../../etc/passwd", true},
		{"File URI", "file:///etc/passwd", true},
		{"VBScript", "vbscript:msgbox(1)", true},

		// Acceptable patterns (not security threats in JWT context)
		{"Email address", "user@example.com", false},
		{"HTTPS URL", "https://example.com/profile", false},
		{"Name with apostrophe", "John O'Brien", false},
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
}

func TestSecurityTokenValidation(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()

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
