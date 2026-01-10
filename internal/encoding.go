package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const (
	maxSegmentLength = 4096 // Maximum JWT segment length
	maxDecodedSize   = 2048 // Maximum decoded payload size
)

func DecodeSegment(segment string, dest any) error {
	segLen := len(segment)
	if segLen == 0 {
		return fmt.Errorf("empty segment")
	}
	if segLen > maxSegmentLength {
		return fmt.Errorf("segment too large: %d bytes exceeds maximum %d", segLen, maxSegmentLength)
	}

	bufLen := base64.RawURLEncoding.DecodedLen(segLen)
	if bufLen > maxDecodedSize {
		return fmt.Errorf("decoded segment too large: %d bytes exceeds maximum %d", bufLen, maxDecodedSize)
	}

	buf := make([]byte, bufLen)
	n, err := base64.RawURLEncoding.Decode(buf, []byte(segment))
	if err != nil {
		return fmt.Errorf("base64 decode failed: %w", err)
	}

	if err := json.Unmarshal(buf[:n], dest); err != nil {
		return fmt.Errorf("json unmarshal failed: %w", err)
	}

	return nil
}
