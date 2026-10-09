package jwt

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Differential tests for the Claims JSON fast paths (claims_json.go).
//
// The fast encoder/decoder must be indistinguishable from encoding/json's
// reflection path: same bytes out, same values and errors in. Every test
// below compares the two implementations directly; the fuzz target extends
// the comparison to arbitrary inputs.

// marshalViaReflection encodes claims with encoding/json's reflection path by
// stripping Claims' own MarshalJSON via a method-less alias.
func marshalViaReflection(c *Claims) ([]byte, error) {
	type claimsAlias Claims
	return json.Marshal((*claimsAlias)(c))
}

// unmarshalViaReflection decodes payload with pure reflection (no
// Claims.UnmarshalJSON), the reference for the fast decoder.
func unmarshalViaReflection(data []byte) (Claims, error) {
	type claimsAlias Claims
	var c claimsAlias
	err := json.Unmarshal(data, &c)
	return Claims(c), err
}

func TestClaimsMarshalDifferential(t *testing.T) {
	now := time.Unix(1750000000, 0).UTC()
	cases := []struct {
		name   string
		claims Claims
	}{
		{"zero", Claims{}},
		{"minimal", Claims{UserID: "user123"}},
		{"built-in fields", Claims{
			UserID: "user123", Username: "alice", Role: "admin",
			SessionID: "sess-1", ClientID: "client-9",
		}},
		{"full", Claims{
			UserID: "u1", Username: "alice", Role: "admin",
			Permissions: []string{"read", "write"},
			Scopes:      []string{"email", "profile"},
			Extra: map[string]any{
				"str":    "v",
				"list":   []string{"a", "b"},
				"num":    42,
				"bignum": int64(1) << 40,
				"flag":   true,
				"null":   nil,
				"flt":    3.5,
			},
			SessionID: "s1", ClientID: "c1",
			RegisteredClaims: RegisteredClaims{
				Issuer: "iss", Subject: "sub",
				Audience:  StringOrSlice{"a1"},
				ExpiresAt: NewNumericDate(now.Add(time.Hour)),
				NotBefore: NewNumericDate(now),
				IssuedAt:  NewNumericDate(now),
				ID:        "tok_abc",
				TokenType: TokenTypeAccess,
			},
		}},
		{"multi audience", Claims{
			RegisteredClaims: RegisteredClaims{Audience: StringOrSlice{"a1", "a2"}},
		}},
		{"multi audience after prior field", Claims{
			UserID:           "u1",
			RegisteredClaims: RegisteredClaims{Audience: StringOrSlice{"a1", "a2"}},
		}},
		{"empty audience slice", Claims{
			RegisteredClaims: RegisteredClaims{Audience: StringOrSlice{}},
		}},
		{"empty slices are omitted", Claims{
			Permissions: []string{},
			Scopes:      nil,
			Extra:       map[string]any{},
		}},
		{"dates needing null", Claims{
			RegisteredClaims: RegisteredClaims{
				ExpiresAt: NewNumericDate(time.Unix(-100, 0).UTC()), // pre-1970 → null
			},
		}},
		{"far future date", Claims{
			RegisteredClaims: RegisteredClaims{
				ExpiresAt: NewNumericDate(time.Unix(maxValidTimestamp+1, 0).UTC()),
			},
		}},
		{"strings needing escapes", Claims{
			UserID:    `quote"backslash\less<greater>amp&`,
			Username:  "tab\tnl\ncr\rctl\x01",
			Role:      "\x7f",      // DEL: not escaped by encoding/json
			SessionID: "日本語emoji🎉", // non-ASCII → stdlib escaping
		}},
		{"u2028", Claims{UserID: "a b"}},
		{"empty strings are omitted", Claims{
			UserID: "", Username: "", Role: "",
		}},
		{"extra nil slice value", Claims{
			Extra: map[string]any{"k": []string(nil)},
		}},
		{"extra empty string slice", Claims{
			Extra: map[string]any{"k": []string{}},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fast, err := json.Marshal(&tc.claims)
			if err != nil {
				t.Fatalf("fast marshal failed: %v", err)
			}
			want, err := marshalViaReflection(&tc.claims)
			if err != nil {
				t.Fatalf("reflection marshal failed: %v", err)
			}
			if string(fast) != string(want) {
				t.Fatalf("marshal mismatch:\n fast: %s\n  ref: %s", fast, want)
			}
		})
	}
}

// TestClaimsMarshalPinsCanonicalOutput pins the exact wire format for one
// representative claim set so accidental format changes surface even if both
// implementations drift together.
func TestClaimsMarshalPinsCanonicalOutput(t *testing.T) {
	c := Claims{
		UserID: "u1", Username: "alice", Role: "admin",
		RegisteredClaims: RegisteredClaims{
			Audience:  StringOrSlice{"aud1"},
			ExpiresAt: NewNumericDate(time.Unix(1750000000, 0).UTC()),
			IssuedAt:  NewNumericDate(time.Unix(1750000000, 0).UTC()),
			ID:        "tok_1",
			TokenType: TokenTypeAccess,
		},
	}
	b, err := json.Marshal(&c)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"user_id":"u1","username":"alice","role":"admin","aud":"aud1","exp":1750000000,"nbf":null,"iat":1750000000,"jti":"tok_1","token_type":"access"}`
	if string(b) != want {
		t.Fatalf("canonical output changed:\n got: %s\nwant: %s", b, want)
	}
}

func TestClaimsUnmarshalDifferential(t *testing.T) {
	cases := []string{
		// Structure and whitespace.
		`{}`,
		` { "user_id" : "u1" } `,
		"{\n\t\"user_id\":\t\"u1\"\r\n}",
		`{"user_id":"u1","username":"alice","role":"admin"}`,
		// All built-in fields.
		`{"user_id":"u1","username":"alice","role":"admin","permissions":["read","write"],"scopes":["email"],"extra":{"k":"v","n":1},"session_id":"s","client_id":"c","iss":"i","sub":"sub","aud":"a","exp":1750000000,"nbf":1750000000,"iat":1750000000,"jti":"j","token_type":"access"}`,
		// null handling.
		`null`,
		`{"exp":null,"nbf":null,"iat":null}`,
		`{"user_id":null}`,
		`{"permissions":null,"scopes":null,"extra":null,"aud":null}`,
		// Escapes in values (fast path must decline these to stdlib).
		`{"username":"a\"b"}`,
		`{"username":"a\\b"}`,
		"{\"username\":\"a\\u0041b\"}",
		`{"username":"a\/b"}`,
		`{"username":"日本語"}`,
		`{"username":"del\x7f"}`,
		`{"username":"ctl` + "\x01" + `ctl"}`,
		// Escaped KEY that decodes to a known field name.
		"{\"\\u0075ser_id\":\"x\"}",
		// Numbers.
		`{"exp":0}`,
		`{"exp":123}`,
		`{"exp":-1}`,
		`{"exp":1.5}`,
		`{"exp":1e3}`,
		`{"exp":17500000000000000000}`, // int64 overflow
		`{"exp":99999999999999}`,       // > maxValidTimestamp
		`{"exp":"1750000000"}`,         // quoted timestamp (supported)
		`{"exp":"abc"}`,
		// Wrong types (stdlib owns the type errors).
		`{"user_id":5}`,
		`{"user_id":true}`,
		`{"user_id":[]}`,
		`{"user_id":{}}`,
		`{"exp":true}`,
		`{"aud":5}`,
		`{"aud":["a",5]}`,
		`{"permissions":"notanarray"}`,
		`{"permissions":[1,2]}`,
		// String-array and extra-map fast paths.
		`{"permissions":["p1","p2","p3"]}`,
		`{"permissions":[]}`,
		`{"permissions":["p1",]}`,
		`{"permissions":["esc\"q"]}`,
		`{"scopes":["s1","s2"]}`,
		`{"extra":{"s":"v","arr":["a","b"],"f":3.5,"i":42,"t":true,"f2":false,"n":null}}`,
		`{"extra":{}}`,
		`{"extra":{"nested":{"deep":1}}}`,
		`{"extra":{"mixed":[1,"a"]}}`,
		"{\"extra\":{\"esc\":\"a\\u0041b\"}}",
		`{"extra":{"num":1e999}}`,      // float64 overflow: stdlib errors
		`{"extra":{"num":1e-999}}`,     // underflow: stdlib errors too
		`{"extra":{"num":1e-320}}`,     // subnormal: both accept
		`{"extra":{"num":01}}`,         // invalid number: stdlib errors
		`{"extra":{"Whitespace":"x"}}`, // folded extra keys are literal map keys
		// Unknown fields are ignored; their values must still scan legally.
		`{"unknown":123}`,
		`{"unknown":null}`,
		`{"unknown":{"nested":[1,2,{"deep":true},["x"]]}}`,
		`{"UNKNOWN":"case sensitive"}`,
		`{"user_id_extra":"prefix not field"}`,
		// Duplicate keys: last wins.
		`{"user_id":"a","user_id":"b"}`,
		`{"exp":1,"exp":1750000000}`,
		`{"extra":{"a":1},"extra":{"b":2}}`,
		// Case-insensitive field matching (encoding/json folds keys).
		`{"Aud":["0","00000000"]}`,
		`{"USER_ID":"upper"}`,
		`{"UserId":"mixed"}`,
		`{"EXP":1750000000}`,
		`{"Token_Type":"access"}`,
		`{"aud":"x","AUD":"y"}`, // folded duplicate: last wins
		// Non-ASCII key folding corner cases (EqualFold 'ſ' ↔ 's').
		"{\"\xc5\xbfub\":\"x\"}", // ſub folds to sub under EqualFold
		"{\"user_id_longer_than_any_field_key\":\"x\",\"user_id\":\"y\"}",
		// StringOrSlice fallbacks inside aud (escaped / non-ASCII values).
		`{"aud":"a\"b"}`,
		`{"aud":"日本語"}`,
		`{"aud":["x","日"]}`,
		`{"aud":["x","a\"b"]}`,
		// Number spellings the scanner must accept or decline identically.
		`{"extra":{"k":1E5}}`,
		`{"extra":{"k":-0}}`,
		`{"extra":{"k":0e0}}`,
		// Malformed JSON — errors must match stdlib's.
		``,
		`   `,
		`{`,
		`}`,
		`{"a"}`,
		`{"a":}`,
		`{,}`,
		`{"a":1,}`,
		`{"a":1} {"b":2}`,
		`{"a":1} trailing`,
		`[1,2]`,
		`"string"`,
		`123`,
		`true`,
		`false`,
		`{"a":01}`,  // leading zero
		`{"a":+1}`,  // plus sign
		`{"a":.5}`,  // bare fraction
		`{"a":1.}`,  // digit required after dot
		`{"a":1e}`,  // digit required after e
		`{"a":1e+}`, // digit required after sign
		`{"a":-}`,   // digit required after minus
		`{"a":tru}`, // truncated literal
		`{"a":truex}`,
		`{"a":[1,]}`,                     // trailing comma in array
		`{"a":"""}`,                      // empty then junk
		`{"a":"unterm`,                   // unterminated string
		`{"a":"bad\q"}`,                  // invalid escape
		`{"a":"bad\u00"}`,                // short unicode escape
		`{"a":"ctl` + "\x01" + `"}`,      // raw control byte in string
		`{"a":"bad utf8` + "\xff" + `"}`, // invalid UTF-8: stdlib rejects on unquote
		`{"a":` + strings.Repeat("[", 50) + strings.Repeat("]", 50) + `}`, // deep-ish nesting
	}

	for _, payload := range cases {
		name := payload
		if len(name) > 48 {
			name = name[:48] + "…"
		}
		t.Run(name, func(t *testing.T) {
			var fast Claims
			errFast := json.Unmarshal([]byte(payload), &fast)

			ref, errRef := unmarshalViaReflection([]byte(payload))

			// Error agreement (both nil or both non-nil with identical text).
			switch {
			case errFast == nil && errRef != nil:
				t.Fatalf("fast accepted, reflection rejected: %v\npayload: %q", errRef, payload)
			case errFast != nil && errRef == nil:
				t.Fatalf("fast rejected (%v), reflection accepted\npayload: %q", errFast, payload)
			case errFast != nil:
				if errFast.Error() != errRef.Error() {
					t.Fatalf("error mismatch:\n fast: %v\n  ref: %v\npayload: %q", errFast, errRef, payload)
				}
				return
			}

			// Value agreement.
			if !reflect.DeepEqual(fast, ref) {
				t.Fatalf("decode mismatch:\n fast: %+v\n  ref: %+v\npayload: %q", fast, ref, payload)
			}

			// Round-trip: re-encoding the fast-decoded claims must equal
			// re-encoding the reference decode.
			fastJSON, err := json.Marshal(&fast)
			if err != nil {
				t.Fatal(err)
			}
			refJSON, err := json.Marshal(&ref)
			if err != nil {
				t.Fatal(err)
			}
			if string(fastJSON) != string(refJSON) {
				t.Fatalf("re-encode mismatch:\n fast: %s\n  ref: %s", fastJSON, refJSON)
			}
		})
	}
}

// TestClaimsUnmarshalPreservesAbsentFields pins the stdlib semantics the
// RefreshInto path depends on: decoding into a non-zero Claims overwrites
// only the fields present in the payload.
func TestClaimsUnmarshalPreservesAbsentFields(t *testing.T) {
	c := Claims{
		UserID: "keep-me",
		Role:   "admin",
		RegisteredClaims: RegisteredClaims{
			Issuer:    "keep-iss",
			ExpiresAt: NewNumericDate(time.Unix(1800000000, 0).UTC()),
		},
	}
	payload := `{"username":"new"}`
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		t.Fatal(err)
	}
	if c.UserID != "keep-me" || c.Role != "admin" || c.Issuer != "keep-iss" {
		t.Fatalf("absent fields were clobbered: %+v", c)
	}
	if c.Username != "new" {
		t.Fatalf("present field not decoded: %+v", c)
	}
	if c.ExpiresAt.Unix() != 1800000000 {
		t.Fatalf("absent exp was clobbered: %+v", c)
	}
}

// TestAppendJSONAppends verifies the append contract: existing bytes are
// preserved, output continues from the end.
func TestAppendJSONAppends(t *testing.T) {
	c := Claims{UserID: "u1"}
	dst := []byte("prefix:")
	out, err := c.AppendJSON(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), "prefix:") {
		t.Fatalf("prefix clobbered: %s", out)
	}
	fresh, err := json.Marshal(&c)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[len(dst):]) != string(fresh) {
		t.Fatalf("appended bytes differ from MarshalJSON:\n got: %s\nwant: %s", out[len(dst):], fresh)
	}
}

// TestAppendJSONExtraMarshalError verifies unsupported Extra values surface
// the same failure the reflection encoder produced.
func TestAppendJSONExtraMarshalError(t *testing.T) {
	c := Claims{Extra: map[string]any{"bad": make(chan int)}}
	if _, err := json.Marshal(&c); err == nil {
		t.Fatal("expected marshal error for channel value")
	}
}

// Direct unit tests for the scanner primitives. The differential tests above
// prove the fast path matches encoding/json end-to-end; these tables pin the
// individual decline/error branches that the end-to-end inputs reach only
// incidentally, so a regression cannot hide behind a coincidental fallback.

// TestUnmarshalFastDeclines drives unmarshalFast directly and asserts the
// fallback sentinel for structurally-doubtful inputs, and nil for inputs the
// scanner fully handles.
func TestUnmarshalFastDeclines(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		wantErr bool // true: errClaimsJSONFallback; false: nil
	}{
		{"empty", "", true},
		{"whitespace only", "  ", true},
		{"not an object", `[1,2]`, true},
		{"unterminated object", `{`, true},
		{"missing value", `{"a":}`, true},
		{"missing colon", `{"a"}`, true},
		{"trailing garbage after object", `{} x`, true},
		{"trailing garbage after value", `{"a":1} {"b":2}`, true},
		{"trailing comma", `{"a":1,}`, true},
		{"leading comma", `{,}`, true},
		{"value ends at EOF", `{"a":`, true},
		{"complete value ends at EOF", `{"a":1`, true},
		{"junk after object value", `{"a":1 x`, true},
		{"key ends at EOF", `{"a`, true},
		{"colon then EOF", `{"a":`, true},
		{"empty object", `{}`, false},
		{"known field", `{"user_id":"u1"}`, false},
		{"unknown long key", `{"user_id_longer_than_any_field_key":1}`, false},
		{"whitespace padded", ` { "user_id" : "u1" } `, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c Claims
			err := c.unmarshalFast([]byte(tc.payload))
			if tc.wantErr && err != errClaimsJSONFallback {
				t.Fatalf("unmarshalFast(%q) err = %v, want errClaimsJSONFallback", tc.payload, err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unmarshalFast(%q) err = %v, want nil", tc.payload, err)
			}
		})
	}
}

// TestScanJSONString pins the string scanner's structural rejections.
func TestScanJSONString(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantEnd int  // 0: expected error
		wantErr bool // true when an error is expected
	}{
		{"plain", `"abc"`, 5, false},
		{"empty", `""`, 2, false},
		{"escaped quote", `"a\"b"`, 6, false},
		{"escaped backslash", `"a\\b"`, 6, false},
		{"unicode escape", "\"a\\u0041b\"", 10, false},
		{"short unicode escape", "\"a\\u00\"", 0, true},
		{"invalid escape", `"a\qb"`, 0, true},
		{"raw control byte", "\"a\x01b\"", 0, true},
		{"unterminated", `"abc`, 0, true},
		{"dangling backslash", `"abc\`, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			end, err := scanJSONString([]byte(tc.input), 0)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("scanJSONString(%q) = %d, want error", tc.input, end)
				}
				return
			}
			if err != nil {
				t.Fatalf("scanJSONString(%q) err = %v", tc.input, err)
			}
			if end != tc.wantEnd {
				t.Fatalf("scanJSONString(%q) = %d, want %d", tc.input, end, tc.wantEnd)
			}
		})
	}
}

// TestScanJSONNumber pins the RFC 8259 grammar enforcement: accepted forms
// return an end index; every invalid form declines with the fallback error.
func TestScanJSONNumber(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantEnd int
		wantErr bool
	}{
		{"zero", "0", 1, false},
		{"negative zero", "-0", 2, false},
		{"integer", "123", 3, false},
		{"negative integer", "-123", 4, false},
		{"fraction", "1.5", 3, false},
		{"exponent", "1e5", 3, false},
		{"capital exponent", "1E5", 3, false},
		{"signed exponent", "1e+5", 4, false},
		{"negative exponent", "1.5e-10", 7, false},
		{"fraction then exponent", "0.5e3", 5, false},
		{"number then comma", "12,", 2, false},
		{"number then space", "12 ", 2, false},
		{"leading zero stops after first 0", "01", 1, false},
		{"double zero stops after first 0", "00", 1, false},
		{"lone minus", "-", 0, true},
		{"digit after dot missing", "1.", 0, true},
		{"bare fraction", ".5", 0, true},
		{"digit after e missing", "1e", 0, true},
		{"digit after sign missing", "1e+", 0, true},
		{"trailing junk halts scan", "1x", 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			end, err := scanJSONNumber([]byte(tc.input), 0)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("scanJSONNumber(%q) = %d, want error", tc.input, end)
				}
				return
			}
			if err != nil {
				t.Fatalf("scanJSONNumber(%q) err = %v", tc.input, err)
			}
			if end != tc.wantEnd {
				t.Fatalf("scanJSONNumber(%q) = %d, want %d", tc.input, end, tc.wantEnd)
			}
		})
	}
}

// TestScanJSONValueDepthLimit verifies nesting beyond encoding/json's limit
// declines rather than recursing: the payload is structurally brace-matched,
// so only the depth guard can stop the scan.
func TestScanJSONValueDepthLimit(t *testing.T) {
	deep := strings.Repeat("[", maxJSONDepth+2) + strings.Repeat("]", maxJSONDepth+2)
	if _, err := scanJSONValue([]byte(deep), 0, 0); err != errClaimsJSONFallback {
		t.Fatalf("deep nesting: err = %v, want errClaimsJSONFallback", err)
	}
}

// TestScanJSONLiteral pins the literal matcher: full match advances, any
// mismatch (truncation, wrong letter, trailing garbage) declines.
func TestScanJSONLiteral(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		lit     string
		wantEnd int
		wantErr bool
	}{
		{"true", "true", "true", 4, false},
		{"false", "false", "false", 5, false},
		{"null", "null", "null", 4, false},
		{"literal then more", "truex", "true", 4, false},
		{"truncated", "tru", "true", 0, true},
		{"wrong letter", "trne", "true", 0, true},
		{"empty input", "", "true", 0, true},
		{"empty literal matches empty", "", "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			end, err := scanJSONLiteral([]byte(tc.input), 0, tc.lit)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("scanJSONLiteral(%q, %q) = %d, want error", tc.input, tc.lit, end)
				}
				return
			}
			if err != nil {
				t.Fatalf("scanJSONLiteral(%q, %q) err = %v", tc.input, tc.lit, err)
			}
			if end != tc.wantEnd {
				t.Fatalf("scanJSONLiteral(%q, %q) = %d, want %d", tc.input, tc.lit, end, tc.wantEnd)
			}
		})
	}
}

// TestScanJSONValueStructure drives every structural guard of the recursive
// value scanner directly: each malformed input must decline with the
// fallback sentinel, and each well-formed input must report its exact end.
func TestScanJSONValueStructure(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantEnd int
		wantErr bool
	}{
		// Well-formed values.
		{"string", `"ab"`, 4, false},
		{"number", "12", 2, false},
		{"true", "true", 4, false},
		{"false", "false", 5, false},
		{"null", "null", 4, false},
		{"empty object", `{}`, 2, false},
		{"object", `{"a":1,"b":[2]}`, 15, false},
		{"object with space", `{ "a" : 1 }`, 11, false},
		{"empty array", `[]`, 2, false},
		{"array", `[1,"a",true]`, 12, false},
		{"nested array", `[[1],[2]]`, 9, false},
		{"value followed by another", `1 2`, 1, false},
		// Object structure guards.
		{"object EOF after open brace", `{`, 0, true},
		{"object non-string key", `{x:1}`, 0, true},
		{"object EOF after key", `{"a"`, 0, true},
		{"object missing colon", `{"a" 1}`, 0, true},
		{"object EOF after colon", `{"a":`, 0, true},
		{"object EOF after value", `{"a":1`, 0, true},
		{"object EOF after comma", `{"a":1,`, 0, true},
		{"object junk after value", `{"a":1 x}`, 0, true},
		// Array structure guards.
		{"array EOF after open bracket", `[`, 0, true},
		{"array EOF after value", `[1`, 0, true},
		{"array EOF after comma", `[1,`, 0, true},
		{"array junk after value", `[1 x]`, 0, true},
		{"array trailing comma reads ] as value", `[1,]`, 0, true},
		// Non-value start.
		{"unexpected byte", `x`, 0, true},
		{"closing bracket is not a value", `]`, 0, true},
		{"closing brace is not a value", `}`, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			end, err := scanJSONValue([]byte(tc.input), 0, 0)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("scanJSONValue(%q) = %d, want error", tc.input, end)
				}
				return
			}
			if err != nil {
				t.Fatalf("scanJSONValue(%q) err = %v", tc.input, err)
			}
			if end != tc.wantEnd {
				t.Fatalf("scanJSONValue(%q) = %d, want %d", tc.input, end, tc.wantEnd)
			}
		})
	}
}

// FuzzClaimsJSON differentially fuzzes the fast paths against encoding/json:
// for arbitrary payloads, both decoders must agree on success/failure,
// decoded values, and error text; both encoders must agree byte-for-byte.
func FuzzClaimsJSON(f *testing.F) {
	seeds := []string{
		`{}`, `null`, `{"user_id":"u1"}`, `{"exp":1750000000}`,
		`{"user_id":"a\"b"}`, `{"aud":["x","y"]}`, `{"extra":{"k":1}}`,
		`{"a":1,}`, `{"a":tru}`, `["x"]`, `{"username":"é"}`,
		"{ \"x\" : [ 1 , 2 ] }", `{"exp":-0}`, `{"user_id":5}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, payload string) {
		data := []byte(payload)

		var fast Claims
		errFast := json.Unmarshal(data, &fast)
		ref, errRef := unmarshalViaReflection(data)

		if (errFast == nil) != (errRef == nil) {
			t.Fatalf("error disagreement: fast=%v ref=%v payload=%q", errFast, errRef, payload)
		}
		if errFast != nil {
			if errFast.Error() != errRef.Error() {
				t.Fatalf("error text disagreement: fast=%q ref=%q payload=%q", errFast, errRef, payload)
			}
			return
		}
		if !reflect.DeepEqual(fast, ref) {
			t.Fatalf("value disagreement: fast=%+v ref=%+v payload=%q", fast, ref, payload)
		}

		fastJSON, errFastM := json.Marshal(&fast)
		refJSON, errRefM := marshalViaReflection(&fast)
		if (errFastM == nil) != (errRefM == nil) {
			t.Fatalf("marshal error disagreement: fast=%v ref=%v", errFastM, errRefM)
		}
		if errFastM == nil && string(fastJSON) != string(refJSON) {
			t.Fatalf("marshal disagreement: fast=%s ref=%s", fastJSON, refJSON)
		}
	})
}
