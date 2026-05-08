package internal

import (
	"encoding/base64"
	"strings"
	"testing"
)

// buildTokenWithHeader constructs a JWT with an arbitrary header JSON string.
func buildTokenWithHeader(t *testing.T, headerJSON, payload, signature string) string {
	t.Helper()
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return headerB64 + "." + payloadB64 + "." + signature
}

// slowPathHeaderBytes returns a JSON header where "alg" is unicode-escaped.
// The resulting bytes contain "a" etc. as literal text,
// which json.Unmarshal decodes as "alg" but extractAlgFromJSON cannot match
// via its fast byte scanner.
func slowPathHeaderBytes(alg string) []byte {
	prefix := []byte("{\"" +
		string([]byte{0x5c, 0x75, 0x30, 0x30, 0x36, 0x31}) +
		string([]byte{0x5c, 0x75, 0x30, 0x30, 0x36, 0x63}) +
		string([]byte{0x5c, 0x75, 0x30, 0x30, 0x36, 0x37}) +
		"\":\"" + alg + "\",\"typ\":\"JWT\"}")
	return prefix
}

func buildSlowPathToken(t *testing.T, method Method, key []byte, payload string) string {
	t.Helper()
	header := slowPathHeaderBytes("HS256")
	headerB64 := base64.RawURLEncoding.EncodeToString(header)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signingString := headerB64 + "." + payloadB64
	sig, err := method.Sign(signingString, key)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	return signingString + "." + sig
}

func TestParseSlowPathUnicodeEscapedAlg(t *testing.T) {
	method, err := GetInternalSigningMethod("HS256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod failed: %v", err)
	}
	key := []byte("test-secret-key-with-sufficient-length-32bytes")

	tokenString := buildSlowPathToken(t, method, key, `{"user_id":"slowpath_test"}`)

	claims := make(map[string]any)
	keyFunc := func(token *Core) (any, error) { return key, nil }

	core, err := ParseWithClaims(tokenString, &claims, keyFunc, "")
	if err != nil {
		t.Fatalf("ParseWithClaims (slow path) failed: %v", err)
	}
	defer ReleaseCore(core)

	if !core.Valid {
		t.Error("Expected valid token")
	}
	if core.Alg != "HS256" {
		t.Errorf("Expected Alg=HS256, got %q", core.Alg)
	}
	if uid, _ := claims["user_id"].(string); uid != "slowpath_test" {
		t.Errorf("Expected user_id=slowpath_test, got %v", claims["user_id"])
	}
}

func TestParseSlowPathErrors(t *testing.T) {
	tests := []struct {
		name    string
		token   func() string
		wantErr string
	}{
		{
			name: "header with no alg field",
			token: func() string {
				return buildTokenWithHeader(t,
					`{"typ":"JWT","kid":"abc"}`,
					`{"sub":"test"}`,
					"fakesignature")
			},
			wantErr: "missing or invalid algorithm",
		},
		{
			name: "empty header JSON object",
			token: func() string {
				return buildTokenWithHeader(t,
					`{}`,
					`{"sub":"test"}`,
					"fakesignature")
			},
			wantErr: "empty header",
		},
		{
			name: "header with alg in value but not as key",
			token: func() string {
				return buildTokenWithHeader(t,
					`{"typ":"JWT","kid":"alg"}`,
					`{"sub":"test"}`,
					"fakesignature")
			},
			wantErr: "missing or invalid algorithm",
		},
		{
			name: "header with insecure algorithm via unicode escape",
			token: func() string {
				header := slowPathHeaderBytes("NONE")
				headerB64 := base64.RawURLEncoding.EncodeToString(header)
				payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
				return headerB64 + "." + payloadB64 + ".fakesig"
			},
			wantErr: "insecure algorithm",
		},
		{
			name: "header with unsupported algorithm via unicode escape",
			token: func() string {
				header := slowPathHeaderBytes("XYZ999")
				headerB64 := base64.RawURLEncoding.EncodeToString(header)
				payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
				return headerB64 + "." + payloadB64 + ".fakesig"
			},
			wantErr: "unsupported signing method",
		},
		{
			name: "invalid JSON in header",
			token: func() string {
				return buildTokenWithHeader(t,
					`{broken json`,
					`{"sub":"test"}`,
					"fakesignature")
			},
			wantErr: "failed to decode header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := make(map[string]any)
			keyFunc := func(token *Core) (any, error) {
				return []byte("test-secret-key-with-sufficient-length-32bytes"), nil
			}
			_, err := ParseWithClaims(tt.token(), &claims, keyFunc, "")
			if err == nil {
				t.Error("Expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestParseSlowPathWithValidSignatureAndExtraFields(t *testing.T) {
	method, err := GetInternalSigningMethod("HS256")
	if err != nil {
		t.Fatalf("GetInternalSigningMethod failed: %v", err)
	}
	key := []byte("test-secret-key-with-sufficient-length-32bytes")

	// Unicode-escaped alg + extra header fields to test full header parsing
	baseHeader := slowPathHeaderBytes("HS256")
	// Append extra field before closing brace
	header := make([]byte, 0, len(baseHeader)+30)
	header = append(header, baseHeader[:len(baseHeader)-1]...) // remove closing }
	header = append(header, []byte(`,"kid":"test-key","x5t":"abc"}`)...)
	headerB64 := base64.RawURLEncoding.EncodeToString(header)
	payload := `{"user_id":"extra_fields_test","role":"admin"}`
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))

	signingString := headerB64 + "." + payloadB64
	sig, err := method.Sign(signingString, key)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	tokenString := signingString + "." + sig

	claims := make(map[string]any)
	keyFunc := func(token *Core) (any, error) { return key, nil }

	core, err := ParseWithClaims(tokenString, &claims, keyFunc, "")
	if err != nil {
		t.Fatalf("ParseWithClaims failed: %v", err)
	}
	defer ReleaseCore(core)

	if !core.Valid {
		t.Error("Expected valid token")
	}
	if core.Alg != "HS256" {
		t.Errorf("Expected Alg=HS256, got %q", core.Alg)
	}
	// Slow path parses full header into map
	if kid, _ := core.Header["kid"].(string); kid != "test-key" {
		t.Errorf("Expected Header[kid]=test-key, got %v", core.Header["kid"])
	}
	if uid, _ := claims["user_id"].(string); uid != "extra_fields_test" {
		t.Errorf("Expected user_id=extra_fields_test, got %v", claims["user_id"])
	}
}

func TestParseSlowPathInvalidSignature(t *testing.T) {
	header := slowPathHeaderBytes("HS256")
	headerB64 := base64.RawURLEncoding.EncodeToString(header)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
	tokenString := headerB64 + "." + payloadB64 + ".aW52YWxpZHNpZ25hdHVyZQ"

	claims := make(map[string]any)
	keyFunc := func(token *Core) (any, error) {
		return []byte("test-secret-key-with-sufficient-length-32bytes"), nil
	}

	core, err := ParseWithClaims(tokenString, &claims, keyFunc, "")
	if err != nil {
		t.Fatalf("ParseWithClaims failed: %v", err)
	}
	defer ReleaseCore(core)

	if core.Valid {
		t.Error("Expected invalid token due to wrong signature")
	}
}

func TestParseSlowPathKeyFuncError(t *testing.T) {
	header := slowPathHeaderBytes("HS256")
	headerB64 := base64.RawURLEncoding.EncodeToString(header)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
	tokenString := headerB64 + "." + payloadB64 + ".fakesignature"

	claims := make(map[string]any)
	keyFunc := func(token *Core) (any, error) {
		return nil, ErrStoreClosed
	}

	_, err := ParseWithClaims(tokenString, &claims, keyFunc, "")
	if err == nil {
		t.Error("Expected error from key function")
	}
	if !strings.Contains(err.Error(), "store is closed") {
		t.Errorf("Expected key func error, got %v", err)
	}
}

func TestExtractAlgFromJSONEdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "alg with extra whitespace around colon",
			input: `{"alg" : "HS256","typ":"JWT"}`,
			want:  "HS256",
		},
		{
			name:  "alg after string value containing alg",
			input: `{"x":"this_has_alg_in_it","alg":"HS512","typ":"JWT"}`,
			want:  "HS512",
		},
		{
			name:  "escaped quote in value before alg key",
			input: `{"x":"test\"alg","alg":"HS256","typ":"JWT"}`,
			want:  "HS256",
		},
		{
			name:  "no alg key at all",
			input: `{"typ":"JWT","sub":"test"}`,
			want:  "",
		},
		{
			name:  "empty JSON object",
			input: `{}`,
			want:  "",
		},
		{
			name:  "alg is only key",
			input: `{"alg":"ES256"}`,
			want:  "ES256",
		},
		{
			name:  "unicode escaped alg key returns empty",
			input: string(slowPathHeaderBytes("HS256")),
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractAlgFromJSON([]byte(tt.input))
			if got != tt.want {
				t.Errorf("extractAlgFromJSON() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSkipJSONStringEdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
		start int
		want  int
	}{
		{
			name:  "simple string",
			input: "\"hello\"rest",
			start: 0,
			want:  7,
		},
		{
			name:  "escaped quote",
			input: "\"he\\\"llo\"rest",
			start: 0,
			want:  9,
		},
		{
			name:  "escaped backslash",
			input: "\"path\\\\file\"rest",
			start: 0,
			want:  12,
		},
		{
			name:  "multiple escapes",
			input: "\"a\\\\b\\\"c\"rest",
			start: 0,
			want:  9,
		},
		{
			name:  "unclosed string",
			input: "\"no end",
			start: 0,
			want:  7,
		},
		{
			name:  "empty string",
			input: "\"\"rest",
			start: 0,
			want:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := skipJSONString([]byte(tt.input), tt.start)
			if got != tt.want {
				t.Errorf("skipJSONString() = %d, want %d", got, tt.want)
			}
		})
	}
}
