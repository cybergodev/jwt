package internal

type Core struct {
	Header    map[string]any `json:"header"`
	Claims    any            `json:"claims"`
	Signature string         `json:"-"`
	Method    Method
	Valid     bool
	Raw       string
}
