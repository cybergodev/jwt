package jwt

import (
	"fmt"
	"maps"
	"slices"
	"sync/atomic"
	"time"

	"github.com/cybergodev/jwt/internal"
)

type Processor struct {
	secretKey        []byte // For HMAC algorithms
	asymmetricKey    any    // For RSA/ECDSA algorithms (private key)
	verificationKey  any    // For RSA/ECDSA verification (public key)
	accessTokenTTL   time.Duration
	refreshTokenTTL  time.Duration
	issuer           string
	audience         string
	signingMethod    SigningMethod
	blacklistManager *internal.Manager
	rateLimiter      RateLimitProvider
	clock            ClockProvider
	isAsymmetric     bool
	closed           atomic.Bool
}

// New creates a new JWT Processor with the given configuration.
// Use DefaultConfig() to obtain a configuration with sensible defaults,
// then modify fields as needed before passing it to New.
// The processor is thread-safe and can be used concurrently by multiple goroutines.
// Always call Close() when done to release resources and securely clear the secret key.
//
// Example (HMAC):
//
//	cfg := jwt.DefaultConfig()
//	cfg.SecretKey = "your-32-byte-secret-key-here..."
//	processor, err := jwt.New(cfg)
//
// Example (RSA):
//
//	cfg := jwt.DefaultConfig()
//	cfg.SigningKey = privateKey
//	cfg.SigningMethod = jwt.SigningMethodRS256
//	processor, err := jwt.New(cfg)
func New(cfg Config) (*Processor, error) {
	// Apply defaults for zero values
	config := normalizeConfig(cfg)

	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Propagate clock to blacklist manager for testability
	if config.Clock != nil {
		config.Blacklist.clock = config.Clock.Now
	}

	manager := config.Blacklist.createManager()

	var rateLimiter RateLimitProvider
	if config.RateLimiter != nil {
		rateLimiter = config.RateLimiter
	} else if config.EnableRateLimit {
		rl := NewRateLimiter(config.RateLimitRate, config.RateLimitWindow)
		if config.Clock != nil {
			rl.nowFunc = config.Clock.Now
		}
		rateLimiter = rl
	}

	clock := config.Clock
	if clock == nil {
		clock = SystemClock{}
	}

	p := &Processor{
		accessTokenTTL:   config.AccessTokenTTL,
		refreshTokenTTL:  config.RefreshTokenTTL,
		issuer:           config.Issuer,
		audience:         config.ExpectedAudience,
		signingMethod:    config.SigningMethod,
		blacklistManager: manager,
		rateLimiter:      rateLimiter,
		clock:            clock,
		isAsymmetric:     config.isAsymmetric(),
	}

	// Set up keys based on algorithm type
	if p.isAsymmetric {
		p.asymmetricKey = config.SigningKey
		// Use VerificationKey if provided, otherwise use SigningKey for verification
		if config.VerificationKey != nil {
			p.verificationKey = config.VerificationKey
		} else {
			p.verificationKey = config.SigningKey
		}
	} else {
		// Copy secret key for HMAC
		p.secretKey = make([]byte, len(config.SecretKey))
		copy(p.secretKey, config.SecretKey)
	}

	return p, nil
}

// Create creates a new JWT access token with the given claims.
// Accepts any type implementing CustomClaims, including *Claims for built-in claims.
// Claims are validated (including deep field validation) before signing.
// The caller's claims struct is not modified; timing fields and defaults
// are set internally during signing and restored afterward.
//
// Example (built-in Claims):
//
//	claims := &jwt.Claims{UserID: "user123", Username: "alice"}
//	token, err := processor.Create(claims)
//
// Example (custom claims):
//
//	claims := &MyClaims{UserID: "123"}
//	token, err := processor.Create(claims)
func (p *Processor) Create(claims CustomClaims) (string, error) {
	if err := p.checkActive(); err != nil {
		return "", err
	}

	if err := validateCustomClaims(claims); err != nil {
		return "", err
	}

	return createTokenWithCustomClaims(p, claims, p.accessTokenTTL)
}

// Validate validates a JWT access token and returns the parsed Claims.
// Returns a value copy of the claims, whether the token is valid, and any error.
// The token is checked for signature validity, expiration, issuer, audience,
// and blacklist status before claims validation.
//
// Example:
//
//	claims, valid, err := processor.Validate(tokenString)
//	if valid {
//	    fmt.Println(claims.UserID)
//	}
func (p *Processor) Validate(tokenString string) (Claims, bool, error) {
	if err := p.checkActive(); err != nil {
		return Claims{}, false, err
	}
	if err := requireToken(tokenString); err != nil {
		return Claims{}, false, err
	}

	claims, err := p.validateTokenFully(tokenString)
	if err != nil {
		return Claims{}, false, err
	}

	return claims, true, nil
}

// CreateRefresh creates a refresh token with the given claims.
// Accepts any type implementing CustomClaims, including *Claims for built-in claims.
// The refresh token uses the configured RefreshTokenTTL instead of AccessTokenTTL.
// Claims are validated (including deep field validation) before signing.
//
// Example:
//
//	claims := &jwt.Claims{UserID: "user123", Username: "alice"}
//	refreshToken, err := processor.CreateRefresh(claims)
func (p *Processor) CreateRefresh(claims CustomClaims) (string, error) {
	if err := p.checkActive(); err != nil {
		return "", err
	}

	if err := validateCustomClaims(claims); err != nil {
		return "", err
	}

	return createTokenWithCustomClaims(p, claims, p.refreshTokenTTL)
}

// Refresh refreshes an existing refresh token and returns a new access token.
// The refresh token is validated (signature, expiration, blacklist) before
// a new access token is created. The original refresh token's claims are copied;
// IssuedAt, ExpiresAt, and ID are reset and regenerated for the new token.
//
// Security note: Claims from the refresh token are validated for standard
// JWT fields (exp, nbf, iss, aud, blacklist) and basic structural validity
// (UserID or Username must be present). Deep field constraints (length limits,
// injection patterns) are not re-checked, trusting they were validated at creation.
//
// Example:
//
//	newAccessToken, err := processor.Refresh(refreshTokenString)
func (p *Processor) Refresh(refreshTokenString string) (string, error) {
	if err := p.checkActive(); err != nil {
		return "", err
	}
	if err := requireToken(refreshTokenString); err != nil {
		return "", err
	}

	claims, err := p.validateTokenFully(refreshTokenString)
	if err != nil {
		return "", err
	}

	claims.IssuedAt = NumericDate{}
	claims.ExpiresAt = NumericDate{}
	claims.ID = ""

	return createTokenWithCustomClaims(p, &claims, p.accessTokenTTL)
}

// RefreshInto refreshes a custom-claims refresh token into a new access token.
// The claims parameter must be a pointer to a type implementing CustomClaims.
// The original claims object is not modified; timing fields (IssuedAt, ExpiresAt, ID)
// are temporarily reset during token creation and restored afterward,
// even if an error or panic occurs.
//
// Security note: Claims from the refresh token are validated for standard
// JWT fields (exp, nbf, iss, aud, blacklist) and basic structural validity.
// Deep field constraints (length limits, injection patterns) are not re-checked,
// trusting they were validated at creation.
//
// Example:
//
//	claims := &MyClaims{}
//	newToken, err := processor.RefreshInto(refreshToken, claims)
func (p *Processor) RefreshInto(refreshTokenString string, claims CustomClaims) (string, error) {
	if err := p.checkActive(); err != nil {
		return "", err
	}
	if err := requireToken(refreshTokenString); err != nil {
		return "", err
	}

	if err := p.validateCustomTokenFully(refreshTokenString, claims); err != nil {
		return "", err
	}

	rc := claims.GetRegisteredClaims()

	// Save original timing fields; restore via defer for panic safety.
	origIssuedAt := rc.IssuedAt
	origExpiresAt := rc.ExpiresAt
	origID := rc.ID
	defer func() {
		rc.IssuedAt = origIssuedAt
		rc.ExpiresAt = origExpiresAt
		rc.ID = origID
	}()

	// Reset timing fields for new access token
	rc.IssuedAt = NumericDate{}
	rc.ExpiresAt = NumericDate{}
	rc.ID = ""

	return createTokenWithCustomClaims(p, claims, p.accessTokenTTL)
}

// Close releases resources and securely clears sensitive data.
// It is safe to call Close multiple times; subsequent calls return ErrProcessorClosed.
// Always call Close when the processor is no longer needed to zero the secret key.
func (p *Processor) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return ErrProcessorClosed
	}

	var closeErr error

	if p.blacklistManager != nil {
		if err := p.blacklistManager.Close(); err != nil {
			closeErr = err
		}
	}

	if p.rateLimiter != nil {
		p.rateLimiter.Close()
	}

	if p.secretKey != nil {
		internal.ZeroBytes(p.secretKey)
		internal.ClearHMACCaches()
	}
	p.asymmetricKey = nil
	p.verificationKey = nil

	return closeErr
}

// IsClosed returns whether the processor has been closed.
func (p *Processor) IsClosed() bool {
	return p.closed.Load()
}

// ParseUnverified parses a token without verifying the signature.
// This is useful for extracting claims from a token when you don't have the key.
//
// WARNING: The returned claims are NOT validated and should NOT be trusted.
// Never use parsed data for authentication or authorization decisions.
// This method exists solely for inspection/logging purposes where signature
// verification is handled by a separate system.
//
// SECURITY: Claims parsed by this method may have been tampered with.
// Always use Validate or ValidateInto for security-sensitive operations.
func (p *Processor) ParseUnverified(tokenString string, claims any) error {
	if err := p.checkActive(); err != nil {
		return err
	}
	if err := requireToken(tokenString); err != nil {
		return err
	}

	_, _, err := internal.ParseUnverified(tokenString, claims)
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	return nil
}

// ValidateInto validates a token and populates the provided custom claims.
// The claims parameter must be a pointer to a type implementing CustomClaims.
// Returns the same claims pointer on success for convenience.
// Note: the provided claims struct is populated in place with parsed token data,
// unlike Validate which returns a value copy.
//
// Example:
//
//	claims := &MyClaims{}
//	result, valid, err := processor.ValidateInto(token, claims)
//	if valid {
//		fmt.Println(result.(*MyClaims).UserID)
//	}
func (p *Processor) ValidateInto(tokenString string, claims CustomClaims) (CustomClaims, bool, error) {
	if err := p.checkActive(); err != nil {
		return nil, false, err
	}
	if err := requireToken(tokenString); err != nil {
		return nil, false, err
	}

	if err := p.validateCustomTokenFully(tokenString, claims); err != nil {
		return nil, false, err
	}

	return claims, true, nil
}

// getSigningKey returns the appropriate signing key based on algorithm type.
// Returns nil if the key is not configured.
func (p *Processor) getSigningKey() any {
	if p.isAsymmetric {
		return p.asymmetricKey
	}
	return p.secretKey
}

// getVerificationKey returns the appropriate key for token verification.
func (p *Processor) getVerificationKey() any {
	if p.isAsymmetric {
		return p.verificationKey
	}
	return p.secretKey
}

// checkActive returns ErrProcessorClosed if the processor has been closed.
func (p *Processor) checkActive() error {
	if p.closed.Load() {
		return ErrProcessorClosed
	}
	return nil
}

// requireToken returns ErrEmptyToken if the token string is empty.
func requireToken(tokenString string) error {
	if tokenString == "" {
		return ErrEmptyToken
	}
	return nil
}

func (p *Processor) checkRateLimit(key string) error {
	if p.rateLimiter == nil || key == "" {
		return nil
	}
	if !p.rateLimiter.Allow(key) {
		return ErrRateLimitExceeded
	}
	return nil
}

func (p *Processor) setRegisteredDefaults(rc *RegisteredClaims, ttl time.Duration) error {
	n := p.clock.Now()
	if rc.IssuedAt.IsZero() {
		rc.IssuedAt = NewNumericDate(n)
	}
	if rc.ExpiresAt.IsZero() {
		rc.ExpiresAt = NewNumericDate(n.Add(ttl))
	}
	if rc.Issuer == "" {
		rc.Issuer = p.issuer
	}
	if rc.ID == "" {
		tokenID, err := internal.GenerateTokenID()
		if err != nil {
			return fmt.Errorf("failed to generate token ID: %w", err)
		}
		rc.ID = tokenID
	}
	return nil
}

func (p *Processor) signClaims(claims any) (string, error) {
	signingMethod, err := internal.GetInternalSigningMethod(string(p.signingMethod))
	if err != nil {
		return "", err
	}

	key := p.getSigningKey()
	if key == nil {
		return "", fmt.Errorf("signing key not configured")
	}

	return internal.SignToken(string(p.signingMethod), claims, signingMethod, key)
}

func (p *Processor) parseToken(tokenString string, claims any) (*internal.Core, error) {
	return internal.ParseWithClaims(tokenString, claims, p.keyFunc)
}

// keyFunc validates the algorithm header and returns the verification key.
func (p *Processor) keyFunc(token *internal.Core) (any, error) {
	alg, ok := token.Header["alg"].(string)
	if !ok || alg != string(p.signingMethod) {
		return nil, ErrAlgorithmMismatch
	}
	return p.getVerificationKey(), nil
}

func (p *Processor) validateRegistered(rc *RegisteredClaims) error {
	now := p.clock.Now()
	if !rc.ExpiresAt.IsZero() && now.After(rc.ExpiresAt.Time) {
		return ErrTokenExpired
	}
	if !rc.NotBefore.IsZero() && now.Before(rc.NotBefore.Time) {
		return ErrTokenNotValidYet
	}
	if p.issuer != "" && rc.Issuer != p.issuer {
		return ErrTokenInvalidIssuer
	}
	if p.audience != "" && !slices.Contains(rc.Audience, p.audience) {
		return ErrTokenInvalidAudience
	}
	return nil
}

func (p *Processor) checkBlacklist(tokenID string) error {
	if tokenID == "" || p.blacklistManager == nil {
		return nil
	}
	isBlacklisted, err := p.blacklistManager.IsBlacklisted(tokenID)
	if err != nil {
		return err
	}
	if isBlacklisted {
		return ErrTokenRevoked
	}
	return nil
}

func copyClaims(dst, src *Claims) {
	*dst = *src
	// Pre-allocate with known capacity for independent backing arrays.
	if n := len(src.Permissions); n > 0 {
		dst.Permissions = make([]string, n)
		copy(dst.Permissions, src.Permissions)
	} else {
		dst.Permissions = nil
	}
	if n := len(src.Scopes); n > 0 {
		dst.Scopes = make([]string, n)
		copy(dst.Scopes, src.Scopes)
	} else {
		dst.Scopes = nil
	}
	if n := len(src.Audience); n > 0 {
		dst.Audience = make([]string, n)
		copy(dst.Audience, src.Audience)
	} else {
		dst.Audience = nil
	}

	// Always allocate a new map to avoid sharing with src after *dst = *src.
	if len(src.Extra) > 0 {
		dst.Extra = make(map[string]any, len(src.Extra))
		maps.Copy(dst.Extra, src.Extra)
	} else {
		dst.Extra = nil
	}
}

func (p *Processor) validateTokenInternal(tokenString string) (Claims, error) {
	claims := getClaims()
	defer putClaims(claims)

	token, err := p.parseToken(tokenString, claims)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	defer internal.ReleaseCore(token)

	if !token.Valid {
		return Claims{}, ErrInvalidToken
	}

	if err := p.validateRegistered(&claims.RegisteredClaims); err != nil {
		return Claims{}, err
	}

	var result Claims
	copyClaims(&result, claims)
	return result, nil
}

// validateTokenFully performs complete token validation: parse, verify signature,
// validate registered claims, check blacklist, and validate custom claims.
// Returns a deep-copied Claims value with no pool obligations for the caller.
func (p *Processor) validateTokenFully(tokenString string) (Claims, error) {
	claims, err := p.validateTokenInternal(tokenString)
	if err != nil {
		return Claims{}, err
	}

	if err := p.checkBlacklist(claims.ID); err != nil {
		return Claims{}, err
	}

	if err := claims.Validate(); err != nil {
		return Claims{}, err
	}

	return claims, nil
}

// validateCustomTokenFully performs complete validation for custom claims types:
// parse, verify signature, validate registered claims, check blacklist,
// and call the custom Validate method.
func (p *Processor) validateCustomTokenFully(tokenString string, claims CustomClaims) error {
	if err := validateTokenIntoCustomClaims(p, tokenString, claims); err != nil {
		return err
	}

	if err := p.checkBlacklist(claims.GetRegisteredClaims().ID); err != nil {
		return err
	}

	return claims.Validate()
}

// Revoke adds a token to the blacklist by its string representation.
// Returns an error if the blacklist is not configured or the token cannot be parsed.
func (p *Processor) Revoke(tokenString string) error {
	if err := p.checkActive(); err != nil {
		return err
	}
	if err := requireToken(tokenString); err != nil {
		return err
	}

	if p.blacklistManager == nil {
		return ErrBlacklistNotConfigured
	}

	return p.blacklistManager.BlacklistTokenString(tokenString)
}

// IsRevoked checks if a token has been revoked by looking up its ID in the blacklist.
// Returns false if the blacklist is not configured or the token ID is empty.
func (p *Processor) IsRevoked(tokenString string) (bool, error) {
	if err := p.checkActive(); err != nil {
		return false, err
	}
	if err := requireToken(tokenString); err != nil {
		return false, err
	}

	tokenID, err := internal.ParseTokenID(tokenString)
	if err != nil {
		return false, err
	}

	if tokenID == "" {
		return false, ErrTokenMissingID
	}

	if p.blacklistManager == nil {
		return false, nil
	}

	return p.blacklistManager.IsBlacklisted(tokenID)
}
