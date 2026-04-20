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
// If no configuration is provided or only zero-value fields are set,
// DefaultConfig() values are used for those fields.
// The processor is thread-safe and can be used concurrently by multiple goroutines.
// Always call Close() when done to release resources and securely clear the secret key.
//
// Example with minimal config (HMAC):
//
//	cfg := jwt.Config{SecretKey: "your-32-byte-secret-key-here..."}
//	processor, err := jwt.New(cfg)
//
// Example with DefaultConfig (HMAC):
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
func New(cfg ...Config) (*Processor, error) {
	var config Config
	if len(cfg) > 0 {
		config = cfg[0]
	}

	// Apply defaults for zero values
	config = normalizeConfig(config)

	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Propagate clock to blacklist manager for testability
	if config.Clock != nil {
		config.Blacklist.clock = config.Clock.Now
	}

	manager := config.Blacklist.CreateManager()

	var rateLimiter RateLimitProvider
	if config.RateLimiter != nil {
		rateLimiter = config.RateLimiter
	} else if config.EnableRateLimit {
		rateLimiter = NewRateLimiter(config.RateLimitRate, config.RateLimitWindow)
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

// CreateToken creates a new JWT access token with the given Claims.
// Claims are validated (including deep field validation) before signing.
//
// Example:
//
//	claims := jwt.Claims{UserID: "user123", Username: "alice"}
//	token, err := processor.CreateToken(claims)
func (p *Processor) CreateToken(claims Claims) (string, error) {
	if err := p.checkActive(); err != nil {
		return "", err
	}

	if err := validateClaims(&claims); err != nil {
		return "", err
	}

	return p.createTokenWithTTL(claims, p.accessTokenTTL)
}

// ValidateToken validates a JWT access token and returns the parsed Claims.
// Returns a value copy of the claims, whether the token is valid, and any error.
// The token is checked for signature validity, expiration, issuer, audience,
// and blacklist status before claims validation.
//
// Example:
//
//	claims, valid, err := processor.ValidateToken(tokenString)
//	if valid {
//	    fmt.Println(claims.UserID)
//	}
func (p *Processor) ValidateToken(tokenString string) (Claims, bool, error) {
	if err := p.checkActive(); err != nil {
		return Claims{}, false, err
	}
	if err := requireToken(tokenString); err != nil {
		return Claims{}, false, err
	}

	claims, err := p.validateTokenInternal(tokenString)
	if err != nil {
		putClaims(claims)
		return Claims{}, false, err
	}

	if err := p.checkBlacklist(claims.ID); err != nil {
		putClaims(claims)
		return Claims{}, false, err
	}

	if err := claims.Validate(); err != nil {
		putClaims(claims)
		return Claims{}, false, err
	}

	result := *claims
	putClaims(claims)
	return result, true, nil
}

// CreateRefreshToken creates a refresh token with the given Claims.
// The refresh token uses the configured RefreshTokenTTL instead of AccessTokenTTL.
// Claims are validated (including deep field validation) before signing.
//
// Example:
//
//	claims := jwt.Claims{UserID: "user123", Username: "alice"}
//	refreshToken, err := processor.CreateRefreshToken(claims)
func (p *Processor) CreateRefreshToken(claims Claims) (string, error) {
	if err := p.checkActive(); err != nil {
		return "", err
	}

	if err := validateClaims(&claims); err != nil {
		return "", err
	}

	return p.createTokenWithTTL(claims, p.refreshTokenTTL)
}

// RefreshToken refreshes an existing refresh token and returns a new access token.
// The refresh token is validated (signature, expiration, blacklist) before
// a new access token is created. The original refresh token's claims are copied;
// IssuedAt, ExpiresAt, and ID are reset and regenerated for the new token.
//
// Example:
//
//	newAccessToken, err := processor.RefreshToken(refreshTokenString)
func (p *Processor) RefreshToken(refreshTokenString string) (string, error) {
	if err := p.checkActive(); err != nil {
		return "", err
	}
	if err := requireToken(refreshTokenString); err != nil {
		return "", err
	}

	claims, err := p.validateTokenInternal(refreshTokenString)
	if err != nil {
		putClaims(claims)
		return "", err
	}
	defer putClaims(claims)

	if err := p.checkBlacklist(claims.ID); err != nil {
		return "", err
	}

	if err := claims.Validate(); err != nil {
		return "", err
	}

	newClaims := *claims
	newClaims.IssuedAt = NumericDate{}
	newClaims.ExpiresAt = NumericDate{}
	newClaims.ID = ""

	return p.createTokenWithTTL(newClaims, p.accessTokenTTL)
}

// RefreshTokenFor refreshes a custom-claims refresh token into a new access token.
// The claims parameter must be a pointer to a type implementing CustomClaims.
// The original claims object is not modified; timing fields (IssuedAt, ExpiresAt, ID)
// are temporarily reset during token creation and restored afterward,
// even if an error or panic occurs.
//
// Example:
//
//	claims := &MyClaims{}
//	newToken, err := processor.RefreshTokenFor(refreshToken, claims)
func (p *Processor) RefreshTokenFor(refreshTokenString string, claims CustomClaims) (string, error) {
	if err := p.checkActive(); err != nil {
		return "", err
	}
	if err := requireToken(refreshTokenString); err != nil {
		return "", err
	}

	if err := validateTokenIntoCustomClaims(p, refreshTokenString, claims); err != nil {
		return "", err
	}

	if err := p.checkBlacklist(claims.GetRegisteredClaims().ID); err != nil {
		return "", err
	}

	if err := claims.Validate(); err != nil {
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
	}

	return closeErr
}

// IsClosed returns whether the processor has been closed.
func (p *Processor) IsClosed() bool {
	return p.closed.Load()
}

// CreateTokenWith creates a token with custom claims type.
// The claims must implement the CustomClaims interface.
// The caller's claims struct is not modified; timing fields and defaults
// are set internally during signing and restored afterward.
//
// Example:
//
//	type MyClaims struct {
//		UserID string `json:"user_id"`
//		jwt.RegisteredClaims
//	}
//
//	func (c *MyClaims) GetRegisteredClaims() *jwt.RegisteredClaims {
//		return &c.RegisteredClaims
//	}
//
//	func (c *MyClaims) Validate() error {
//		if c.UserID == "" {
//			return errors.New("user_id is required")
//		}
//		return nil
//	}
//
//	claims := &MyClaims{UserID: "123"}
//	token, err := processor.CreateTokenWith(claims)
func (p *Processor) CreateTokenWith(claims CustomClaims) (string, error) {
	if err := p.checkActive(); err != nil {
		return "", err
	}

	if err := validateCustomClaims(claims); err != nil {
		return "", err
	}

	return createTokenWithCustomClaims(p, claims, p.accessTokenTTL)
}

// ValidateTokenFor validates a token and populates the provided custom claims.
// The claims parameter must be a pointer to a type implementing CustomClaims.
// Returns the same claims pointer on success for convenience.
// Note: the provided claims struct is populated in place with parsed token data,
// unlike ValidateToken which returns a value copy.
//
// Example:
//
//	claims := &MyClaims{}
//	result, valid, err := processor.ValidateTokenFor(token, claims)
//	if valid {
//		fmt.Println(result.(*MyClaims).UserID)
//	}
func (p *Processor) ValidateTokenFor(tokenString string, claims CustomClaims) (CustomClaims, bool, error) {
	if err := p.checkActive(); err != nil {
		return nil, false, err
	}
	if err := requireToken(tokenString); err != nil {
		return nil, false, err
	}

	if err := validateTokenIntoCustomClaims(p, tokenString, claims); err != nil {
		return nil, false, err
	}

	if err := p.checkBlacklist(claims.GetRegisteredClaims().ID); err != nil {
		return nil, false, err
	}

	if err := claims.Validate(); err != nil {
		return nil, false, err
	}

	return claims, true, nil
}

// ValidateTokenWith validates a token with custom claims.
//
// Deprecated: Use ValidateTokenFor instead.
func (p *Processor) ValidateTokenWith(tokenString string, claims CustomClaims) (CustomClaims, bool, error) {
	return p.ValidateTokenFor(tokenString, claims)
}

// CreateRefreshTokenWith creates a refresh token with custom claims type.
// The claims must implement the CustomClaims interface.
// The refresh token uses the configured RefreshTokenTTL instead of AccessTokenTTL.
//
// Example:
//
//	claims := &MyClaims{UserID: "123"}
//	refreshToken, err := processor.CreateRefreshTokenWith(claims)
func (p *Processor) CreateRefreshTokenWith(claims CustomClaims) (string, error) {
	if err := p.checkActive(); err != nil {
		return "", err
	}

	if err := validateCustomClaims(claims); err != nil {
		return "", err
	}

	return createTokenWithCustomClaims(p, claims, p.refreshTokenTTL)
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
	return internal.ParseWithClaims(tokenString, claims, func(token *internal.Core) (any, error) {
		if alg, ok := token.Header["alg"].(string); !ok || alg != string(p.signingMethod) {
			return nil, ErrInvalidToken
		}
		return p.getVerificationKey(), nil
	})
}

func (p *Processor) validateRegistered(rc *RegisteredClaims) error {
	now := p.clock.Now()
	if !rc.ExpiresAt.IsZero() && now.After(rc.ExpiresAt.Time) {
		return ErrTokenExpired
	}
	if !rc.NotBefore.IsZero() && now.Before(rc.NotBefore.Time) {
		return ErrTokenNotValidYet
	}
	if rc.Issuer != "" && rc.Issuer != p.issuer {
		return ErrTokenInvalidIssuer
	}
	if p.audience != "" && !slices.Contains(rc.Audience, p.audience) {
		return ErrInvalidToken
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

func (p *Processor) createTokenWithTTL(claims Claims, ttl time.Duration) (string, error) {
	rateLimitKey := claims.Subject
	if rateLimitKey == "" {
		rateLimitKey = claims.UserID
	}
	if err := p.checkRateLimit(rateLimitKey); err != nil {
		return "", err
	}

	claimsCopy := getClaims()
	defer putClaims(claimsCopy)

	copyClaims(claimsCopy, &claims)

	if err := p.setRegisteredDefaults(&claimsCopy.RegisteredClaims, ttl); err != nil {
		return "", err
	}

	return p.signClaims(claimsCopy)
}

func copyClaims(dst, src *Claims) {
	*dst = *src
	// Use [:0:0] to force new backing array allocation.
	// After *dst = *src, slices share the same backing array.
	// Plain append([:0], ...) would reuse that shared array;
	// setting cap=0 via [:0:0] forces append to allocate independently.
	dst.Permissions = append(dst.Permissions[:0:0], src.Permissions...)
	dst.Scopes = append(dst.Scopes[:0:0], src.Scopes...)
	dst.Audience = append(dst.Audience[:0:0], src.Audience...)

	// Always allocate a new map to avoid sharing with src after *dst = *src.
	if len(src.Extra) > 0 {
		dst.Extra = make(map[string]any, len(src.Extra))
		maps.Copy(dst.Extra, src.Extra)
	} else {
		dst.Extra = nil
	}
}

func (p *Processor) validateTokenInternal(tokenString string) (*Claims, error) {
	claims := getClaims()

	token, err := p.parseToken(tokenString, claims)
	if err != nil {
		return claims, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if token != nil {
		defer internal.ReleaseCore(token)
	}

	if !token.Valid {
		return claims, ErrInvalidToken
	}

	return claims, p.validateRegistered(&claims.RegisteredClaims)
}

// RevokeToken adds a token to the blacklist by its string representation.
// Returns an error if the blacklist is not configured or the token cannot be parsed.
func (p *Processor) RevokeToken(tokenString string) error {
	if err := p.checkActive(); err != nil {
		return err
	}
	if err := requireToken(tokenString); err != nil {
		return err
	}

	if p.blacklistManager == nil {
		return fmt.Errorf("blacklist not configured")
	}

	return p.blacklistManager.BlacklistTokenString(tokenString)
}

// IsTokenRevoked checks if a token has been revoked by looking up its ID in the blacklist.
// Returns false if the blacklist is not configured or the token ID is empty.
func (p *Processor) IsTokenRevoked(tokenString string) (bool, error) {
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
