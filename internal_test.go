package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cybergodev/jwt/internal"
)

func TestCoreTokenParsing(t *testing.T) {
	processor, err := newTestProcessor(testSecretKey)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := Claims{
		UserID:   "user123",
		Username: "testuser",
	}

	token, err := processor.Create(&claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	parsedClaims := &Claims{}
	coreToken, err := internal.ParseWithClaims(token, parsedClaims, func(token *internal.Core) (any, error) {
		return []byte(testSecretKey), nil
	}, "")

	if err != nil {
		t.Fatalf("Failed to parse token with core: %v", err)
	}

	if coreToken == nil {
		t.Fatal("Parsed token should not be nil")
	}

	if !coreToken.Valid {
		t.Error("Parsed token should be valid")
	}

	if parsedClaims.UserID != claims.UserID {
		t.Errorf("Expected UserID=%s, got UserID=%s", claims.UserID, parsedClaims.UserID)
	}
}

func TestCoreDecodeSegment(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(t *testing.T, decoded map[string]any)
	}{
		{
			name: "valid base64url",
			input: func() string {
				d, _ := json.Marshal(map[string]any{"test": "value", "num": 123})
				return base64.RawURLEncoding.EncodeToString(d)
			}(),
			check: func(t *testing.T, decoded map[string]any) {
				if decoded["test"] != "value" {
					t.Errorf("Expected test=value, got test=%v", decoded["test"])
				}
			},
		},
		{
			name:    "invalid base64url",
			input:   "invalid-base64!",
			wantErr: true,
		},
		{
			name:    "empty segment",
			input:   "",
			wantErr: true,
		},
		{
			name:    "extremely long segment",
			input:   strings.Repeat("a", 10000),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var decoded map[string]any
			err := internal.DecodeSegment(tt.input, &decoded)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, decoded)
			}
		})
	}
}

func TestClaimsPool(t *testing.T) {
	claims1 := getClaims()
	if claims1 == nil {
		t.Fatal("getClaims should return non-nil claims")
	}

	claims1.UserID = "test-user"
	claims1.Username = "test-username"
	claims1.Permissions = []string{"read"}
	claims1.Extra = map[string]any{"key": "value"}

	putClaims(claims1)

	claims2 := getClaims()
	if claims2 == nil {
		t.Fatal("getClaims should return non-nil claims after put")
	}

	if claims2.UserID != "" {
		t.Error("Claims from pool should have UserID reset")
	}
	if claims2.Username != "" {
		t.Error("Claims from pool should have Username reset")
	}
	if claims2.Permissions != nil {
		t.Error("Claims from pool should have Permissions reset to nil")
	}
	if claims2.Extra != nil {
		t.Error("Claims from pool should have Extra reset to nil")
	}

	putClaims(claims2)
}

func TestClockProviderIntegration(t *testing.T) {
	fixedTime := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	cfg.SecretKey = testSecretKey
	cfg.Clock = FixedClock{T: fixedTime}

	processor, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create processor: %v", err)
	}
	defer func() { _ = processor.Close() }() // best-effort cleanup

	claims := Claims{UserID: "clock-user", Username: "test"}
	token, err := processor.Create(&claims)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	parsed, valid, err := processor.Validate(token)
	if err != nil || !valid {
		t.Fatalf("Token should be valid: %v", err)
	}

	// IssuedAt should match the fixed clock time
	if !parsed.IssuedAt.Equal(fixedTime) {
		t.Errorf("IssuedAt = %v, want %v", parsed.IssuedAt, fixedTime)
	}
}
