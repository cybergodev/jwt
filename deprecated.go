package jwt

// Deprecated methods — thin wrappers for backward compatibility.
// These will be removed in a future major version.

// CreateFor creates a token with custom claims type.
//
// Deprecated: Use Create instead. Create now accepts CustomClaims directly.
func (p *Processor) CreateFor(claims CustomClaims) (string, error) {
	return p.Create(claims)
}

// ValidateFor validates a token and populates the provided custom claims.
//
// Deprecated: Use ValidateInto instead.
func (p *Processor) ValidateFor(tokenString string, claims CustomClaims) (CustomClaims, bool, error) {
	return p.ValidateInto(tokenString, claims)
}

// CreateRefreshFor creates a refresh token with custom claims type.
//
// Deprecated: Use CreateRefresh instead. CreateRefresh now accepts CustomClaims directly.
func (p *Processor) CreateRefreshFor(claims CustomClaims) (string, error) {
	return p.CreateRefresh(claims)
}

// RefreshFor refreshes a custom-claims refresh token into a new access token.
//
// Deprecated: Use RefreshInto instead.
func (p *Processor) RefreshFor(refreshTokenString string, claims CustomClaims) (string, error) {
	return p.RefreshInto(refreshTokenString, claims)
}
