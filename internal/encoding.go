package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"unsafe"
)

const (
	maxSegmentLength = 4096 // Maximum JWT segment length
	maxDecodedSize   = 2048 // Maximum decoded payload size
)

// decodeBufPool pools byte slices for base64 decoding operations.
// JWT segments are typically small (< 512 bytes), so we use a reasonable
// initial capacity to reduce allocations while avoiding waste.
var decodeBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 512)
		return &buf
	},
}

func getDecodeBuf() *[]byte {
	return decodeBufPool.Get().(*[]byte)
}

func putDecodeBuf(buf *[]byte) {
	if cap(*buf) <= 2048 {
		*buf = (*buf)[:0]
		decodeBufPool.Put(buf)
	}
}

// stringToBytes converts a string to a byte slice without allocation.
// The returned byte slice must not be modified.
// Uses unsafe for zero allocation conversion.
func stringToBytes(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

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

	bufPtr := getDecodeBuf()
	defer putDecodeBuf(bufPtr)

	// Grow buffer if needed
	if cap(*bufPtr) < bufLen {
		*bufPtr = make([]byte, 0, bufLen)
	}

	buf := (*bufPtr)[:bufLen]
	n, err := base64.RawURLEncoding.Decode(buf, stringToBytes(segment))
	if err != nil {
		return fmt.Errorf("base64 decode failed: %w", err)
	}

	if err := json.Unmarshal(buf[:n], dest); err != nil {
		return fmt.Errorf("json unmarshal failed: %w", err)
	}

	return nil
}
