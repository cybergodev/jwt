package jwt

import (
	"testing"
	"time"
)

func TestTimezoneConfiguration(t *testing.T) {
	// Save original timezone
	originalTz := GetTimezone()
	defer SetTimezone(originalTz)

	// Test setting UTC timezone
	SetTimezone(time.UTC)
	if GetTimezone() != time.UTC {
		t.Error("Failed to set timezone to UTC")
	}

	// Test setting local timezone
	SetTimezone(time.Local)
	if GetTimezone() != time.Local {
		t.Error("Failed to set timezone to Local")
	}

	// Test setting custom timezone
	tokyoTz, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Skip("Cannot load Tokyo timezone, skipping test")
	}
	SetTimezone(tokyoTz)
	if GetTimezone() != tokyoTz {
		t.Error("Failed to set timezone to Tokyo")
	}
}

func TestNumericDateWithTimezone(t *testing.T) {
	now := time.Now()

	// Test default timezone
	nd1 := NewNumericDate(now)
	if nd1.Time.Location() != GetTimezone() {
		t.Errorf("NewNumericDate should use default timezone, got %v, expected %v",
			nd1.Time.Location(), GetTimezone())
	}

	// Test with UTC timezone
	SetTimezone(time.UTC)
	nd2 := NewNumericDate(now)
	if nd2.Time.Location() != time.UTC {
		t.Errorf("NewNumericDate should use UTC timezone, got %v", nd2.Time.Location())
	}

	// Test with custom timezone
	tokyoTz, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Skip("Cannot load Tokyo timezone, skipping test")
	}
	SetTimezone(tokyoTz)
	nd3 := NewNumericDate(now)
	if nd3.Time.Location() != tokyoTz {
		t.Errorf("NewNumericDate should use specified timezone, got %v, expected %v",
			nd3.Time.Location(), tokyoTz)
	}
}

func TestCreateTokenWithTimezone(t *testing.T) {
	secretKey := "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"
	claims := Claims{UserID: "test_user", Username: "test"}

	// Save original timezone
	originalTz := GetTimezone()
	defer SetTimezone(originalTz)

	// Test UTC timezone token creation
	SetTimezone(time.UTC)
	token1, err := CreateToken(secretKey, claims)
	if err != nil {
		t.Fatalf("Failed to create UTC token: %v", err)
	}

	// Validate token
	parsedClaims1, valid1, err := ValidateToken(secretKey, token1)
	if err != nil {
		t.Fatalf("Failed to validate UTC token: %v", err)
	}
	if !valid1 {
		t.Error("UTC token should be valid")
	}
	if parsedClaims1.UserID != claims.UserID {
		t.Errorf("UserID mismatch: got %s, expected %s", parsedClaims1.UserID, claims.UserID)
	}

	// Test local timezone token creation
	SetTimezone(time.Local)
	token2, err := CreateToken(secretKey, claims)
	if err != nil {
		t.Fatalf("Failed to create local timezone token: %v", err)
	}

	// Validate token
	parsedClaims2, valid2, err := ValidateToken(secretKey, token2)
	if err != nil {
		t.Fatalf("Failed to validate local timezone token: %v", err)
	}
	if !valid2 {
		t.Error("Local timezone token should be valid")
	}
	if parsedClaims2.UserID != claims.UserID {
		t.Errorf("UserID mismatch: got %s, expected %s", parsedClaims2.UserID, claims.UserID)
	}
}
