package internal

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestDecodeHeaderAlgBufferPaths covers DecodeHeaderAlg's two buffer paths:
// the stack buffer for typical headers (decoded size <= headerStackBuf) and
// the pooled fallback for larger ones, plus the size guards.
func TestDecodeHeaderAlgBufferPaths(t *testing.T) {
	encode := func(json string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(json))
	}

	// Typical header: decodes to 27 bytes — well within the stack buffer.
	typical := encode(`{"alg":"HS256","typ":"JWT"}`)
	if got := DecodeHeaderAlg(typical); got != "HS256" {
		t.Errorf("DecodeHeaderAlg(typical) = %q, want %q", got, "HS256")
	}

	// Oversized-but-legal header: decoded size beyond headerStackBuf must
	// still resolve alg via the pooled-buffer path, wherever alg sits.
	kid := strings.Repeat("k", 300)
	for name, header := range map[string]string{
		"alg first":  `{"alg":"ES384","typ":"JWT","kid":"` + kid + `"}`,
		"alg last":   `{"typ":"JWT","kid":"` + kid + `","alg":"PS512"}`,
		"no alg":     `{"typ":"JWT","kid":"` + kid + `"}`,
		"non-string": `{"typ":"JWT","kid":"` + kid + `","alg":123}`,
	} {
		want := ""
		switch name {
		case "alg first":
			want = "ES384"
		case "alg last":
			want = "PS512"
		}
		if got := DecodeHeaderAlg(encode(header)); got != want {
			t.Errorf("DecodeHeaderAlg(%s) = %q, want %q", name, got, want)
		}
	}

	// Guard rails.
	if got := DecodeHeaderAlg(strings.Repeat("A", maxSegmentLength+1)); got != "" {
		t.Errorf("DecodeHeaderAlg(oversized) = %q, want empty", got)
	}
	if got := DecodeHeaderAlg("!!!not-base64!!!"); got != "" {
		t.Errorf("DecodeHeaderAlg(invalid base64) = %q, want empty", got)
	}
	if got := DecodeHeaderAlg(""); got != "" {
		t.Errorf("DecodeHeaderAlg(empty) = %q, want empty", got)
	}
}
