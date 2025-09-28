package jwt

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

var (
	// defaultTimezone holds the default timezone for JWT timestamps
	// Using atomic.Pointer for lock-free reads in the common case
	defaultTimezone atomic.Pointer[time.Location]
)

func init() {
	// Initialize with local timezone
	defaultTimezone.Store(time.Local)
}

// SetTimezone sets the default timezone for JWT timestamps
func SetTimezone(tz *time.Location) {
	if tz == nil {
		tz = time.Local
	}
	defaultTimezone.Store(tz)
}

// GetTimezone returns the current default timezone
func GetTimezone() *time.Location {
	return defaultTimezone.Load()
}

// NumericDate represents a JSON numeric date value as specified in RFC 7519
type NumericDate struct {
	time.Time
}

// NewNumericDate creates a new NumericDate from time.Time using default timezone
func NewNumericDate(t time.Time) NumericDate {
	return NumericDate{Time: t.In(GetTimezone())}
}

// MarshalJSON implements json.Marshaler interface
func (date *NumericDate) MarshalJSON() ([]byte, error) {
	if date.Time.IsZero() {
		return []byte("null"), nil
	}

	return []byte(fmt.Sprintf("%d", date.Unix())), nil
}

// UnmarshalJSON implements json.Unmarshaler interface
func (date *NumericDate) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)

	if s == "null" || s == "" {
		date.Time = time.Time{}
		return nil
	}

	// Try parsing as Unix timestamp (simple implementation)
	var unix int64
	if _, err := fmt.Sscanf(s, "%d", &unix); err == nil {
		// Unix timestamps are always in UTC, then convert to default timezone for display
		utcTime := time.Unix(unix, 0).UTC()
		tz := GetTimezone()
		date.Time = utcTime.In(tz)
		return nil
	}

	// Try parsing as RFC3339 string
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		// RFC3339 includes timezone info, convert to default timezone for consistency
		tz := GetTimezone()
		date.Time = t.In(tz)
		return nil
	}

	return fmt.Errorf("invalid time format: %s", s)
}
