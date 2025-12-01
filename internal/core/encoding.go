package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func DecodeSegment(segment string, dest any) error {
	segLen := len(segment)
	if segLen == 0 || segLen > 4096 {
		return fmt.Errorf("invalid segment length")
	}

	bufLen := base64.RawURLEncoding.DecodedLen(segLen)
	if bufLen > 2048 {
		return fmt.Errorf("segment too large")
	}

	buf := make([]byte, bufLen)
	n, err := base64.RawURLEncoding.Decode(buf, []byte(segment))
	if err != nil {
		return fmt.Errorf("decode failed: %w", err)
	}

	if err := json.Unmarshal(buf[:n], dest); err != nil {
		return fmt.Errorf("unmarshal failed: %w", err)
	}

	return nil
}
