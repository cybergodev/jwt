package jwt

import (
	"fmt"
	"time"
)

type NumericDate struct {
	time.Time
}

func NewNumericDate(t time.Time) NumericDate {
	return NumericDate{Time: t}
}

func (date *NumericDate) MarshalJSON() ([]byte, error) {
	if date.Time.IsZero() {
		return []byte("null"), nil
	}

	unix := date.Unix()
	if unix < 0 || unix > 253402300799 {
		return []byte("null"), nil
	}

	return fmt.Appendf(nil, "%d", unix), nil
}

func (date *NumericDate) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		date.Time = time.Time{}
		return nil
	}

	s := string(b)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}

	if s == "" || s == "null" {
		date.Time = time.Time{}
		return nil
	}

	var unix int64
	if _, err := fmt.Sscanf(s, "%d", &unix); err != nil {
		return fmt.Errorf("invalid time format: expected unix timestamp, got %s", s)
	}

	if unix < 0 || unix > 253402300799 {
		return fmt.Errorf("invalid unix timestamp: %d", unix)
	}

	date.Time = time.Unix(unix, 0).UTC()
	return nil
}
