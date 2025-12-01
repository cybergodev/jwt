package jwt

import (
	"fmt"
	"time"
)

// NumericDate represents a JSON numeric date value as specified in RFC 7519.
// It stores time as Unix timestamp (seconds since epoch) for JWT compatibility.
type NumericDate struct {
	time.Time
}

// NewNumericDate creates a new NumericDate from time.Time
func NewNumericDate(t time.Time) NumericDate {
	return NumericDate{Time: t}
}

// MarshalJSON implements json.Marshaler interface
func (date *NumericDate) MarshalJSON() ([]byte, error) {
	if date.Time.IsZero() {
		return []byte("null"), nil
	}

	return fmt.Appendf(nil, "%d", date.Unix()), nil
}

// UnmarshalJSON implements json.Unmarshaler interface
func (date *NumericDate) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		date.Time = time.Time{}
		return nil
	}

	s := string(b)
	if s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}

	if s == "" {
		date.Time = time.Time{}
		return nil
	}

	var unix int64
	if _, err := fmt.Sscanf(s, "%d", &unix); err == nil {
		if unix < 0 || unix > 253402300799 {
			return fmt.Errorf("invalid unix timestamp: %d", unix)
		}
		date.Time = time.Unix(unix, 0).UTC()
		return nil
	}

	return fmt.Errorf("invalid time format: expected unix timestamp, got %s", s)
}
