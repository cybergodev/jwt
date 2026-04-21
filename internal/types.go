package internal

type Core struct {
	Header    map[string]any `json:"header"`
	Claims    any            `json:"claims"`
	Signature string         `json:"-"`
	Method    Method
	Valid     bool
	Raw       string
	// Alg caches the algorithm extracted during fast-path parsing so keyFunc
	// can read it without storing the string as an interface in Header (which
	// causes one heap allocation per parse for the string→any boxing).
	// Empty when the slow path (full header decode) was used.
	Alg string
}
