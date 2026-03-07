package jwt

import (
	"fmt"
	"maps"
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

	manager := config.Blacklist.CreateManager()

	var rateLimiter RateLimitProvider
	if config.RateLimiter != nil {
		rateLimiter = config.RateLimiter
	} else if config.EnableRateLimit {
		rateLimiter = NewRateLimiter(config.RateLimitRate, config.RateLimitWindow)
	}

	p := &Processor{
		accessTokenTTL:   config.AccessTokenTTL,
		refreshTokenTTL:  config.RefreshTokenTTL,
		issuer:           config.Issuer,
		signingMethod:    config.SigningMethod,
		blacklistManager: manager,
		rateLimiter:      rateLimiter,
		clock:            SystemClock{},
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

func (p *Processor) CreateToken(claims Claims) (string, error) {
	if p.closed.Load() {
		return "", ErrProcessorClosed
	}

	if err := validateClaims(&claims); err != nil {
		return "", err
	}

	return p.createTokenWithTTL(claims, p.accessTokenTTL)
}

func (p *Processor) ValidateToken(tokenString string) (Claims, bool, error) {
	if p.closed.Load() {
		return Claims{}, false, ErrProcessorClosed
	}

	if tokenString == "" {
		return Claims{}, false, ErrEmptyToken
	}

	claims, valid, err := p.validateTokenInternal(tokenString)
	if err != nil {
		putClaims(claims)
		return Claims{}, false, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !valid {
		putClaims(claims)
		return Claims{}, false, nil
	}

	if claims.ID != "" {
		if isBlacklisted, err := p.blacklistManager.IsBlacklisted(claims.ID); err != nil {
			putClaims(claims)
			return Claims{}, false, err
		} else if isBlacklisted {
			putClaims(claims)
			return Claims{}, false, ErrTokenRevoked
		}
	}

	result := *claims
	putClaims(claims)
	return result, valid, nil
}

func (p *Processor) CreateRefreshToken(claims Claims) (string, error) {
	if p.closed.Load() {
		return "", ErrProcessorClosed
	}

	if err := validateClaims(&claims); err != nil {
		return "", err
	}

	return p.createTokenWithTTL(claims, p.refreshTokenTTL)
}

func (p *Processor) RefreshToken(refreshTokenString string) (string, error) {
	if p.closed.Load() {
		return "", ErrProcessorClosed
	}

	if refreshTokenString == "" {
		return "", ErrEmptyToken
	}

	claims, valid, err := p.validateTokenInternal(refreshTokenString)
	if err != nil {
		putClaims(claims)
		return "", err
	}
	defer putClaims(claims)

	if !valid {
		return "", ErrInvalidToken
	}

	newClaims := *claims
	newClaims.IssuedAt = NumericDate{}
	newClaims.ExpiresAt = NumericDate{}
	newClaims.ID = ""

	return p.createTokenWithTTL(newClaims, p.accessTokenTTL)
}

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

func (p *Processor) IsClosed() bool {
	return p.closed.Load()
}

// CreateTokenWith creates a token with custom claims type.
// The claims must implement the CustomClaims interface.
// This is the recommended way to create tokens with custom claim types.
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
	return CreateTokenWithClaims(p, claims)
}

// ValidateTokenWith validates a token and populates the provided claims.
// The claims parameter must be a pointer to a type implementing CustomClaims.
// Returns the same claims pointer on success for convenience.
//
// Example:
//
//	claims := &MyClaims{}
//	result, valid, err := processor.ValidateTokenWith(token, claims)
//	if valid {
//		fmt.Println(result.(*MyClaims).UserID)
//	}
func (p *Processor) ValidateTokenWith(tokenString string, claims CustomClaims) (CustomClaims, bool, error) {
	return ValidateTokenWithClaims(p, tokenString, claims)
}

// CreateRefreshTokenWith creates a refresh token with custom claims type.
// The claims must implement the CustomClaims interface.
func (p *Processor) CreateRefreshTokenWith(claims CustomClaims) (string, error) {
	return CreateRefreshTokenWithClaims(p, claims)
}

// getSigningKey returns the appropriate signing key based on algorithm type.
// Returns nil if the key is not configured.
func (p *Processor) getSigningKey() any {
	if p.isAsymmetric {
		return p.asymmetricKey
	}
	return p.secretKey
}

func (p *Processor) createTokenWithTTL(claims Claims, ttl time.Duration) (string, error) {
	if p.rateLimiter != nil && !p.rateLimiter.Allow(claims.UserID) {
		return "", ErrRateLimitExceeded
	}

	claimsCopy := getClaims()
	defer putClaims(claimsCopy)

	copyClaims(claimsCopy, &claims)

	n := p.clock.Now()
	if claimsCopy.IssuedAt.IsZero() {
		claimsCopy.IssuedAt = NewNumericDate(n)
	}
	if claimsCopy.ExpiresAt.IsZero() {
		claimsCopy.ExpiresAt = NewNumericDate(n.Add(ttl))
	}
	if claimsCopy.Issuer == "" {
		claimsCopy.Issuer = p.issuer
	}
	if claimsCopy.ID == "" {
		tokenID, err := internal.GenerateTokenID()
		if err != nil {
			return "", fmt.Errorf("failed to generate token ID: %w", err)
		}
		claimsCopy.ID = tokenID
	}

	signingMethod, err := internal.GetInternalSigningMethod(string(p.signingMethod))
	if err != nil {
		return "", err
	}

	token := internal.NewTokenWithClaims(signingMethod, claimsCopy)

	// Use appropriate key based on algorithm type
	key := p.getSigningKey()
	if key == nil {
		return "", fmt.Errorf("signing key not configured")
	}
	return token.SignedString(key)
}

func copyClaims(dst, src *Claims) {
	*dst = *src
	dst.Permissions = append(dst.Permissions[:0], src.Permissions...)
	dst.Scopes = append(dst.Scopes[:0], src.Scopes...)
	dst.Audience = append(dst.Audience[:0], src.Audience...)

	if len(src.Extra) > 0 {
		if dst.Extra == nil {
			dst.Extra = make(map[string]any, len(src.Extra))
		} else {
			clear(dst.Extra)
		}
		maps.Copy(dst.Extra, src.Extra)
	} else if dst.Extra != nil {
		clear(dst.Extra)
	}
}

func (p *Processor) validateTokenInternal(tokenString string) (*Claims, bool, error) {
	claims := getClaims()

	token, err := internal.ParseWithClaims(tokenString, claims, func(token *internal.Core) (any, error) {
		if alg, ok := token.Header["alg"].(string); !ok || alg != string(p.signingMethod) {
			return nil, ErrInvalidToken
		}
		// Use appropriate key based on algorithm type
		if p.isAsymmetric {
			return p.verificationKey, nil
		}
		return p.secretKey, nil
	})

	if err != nil {
		return claims, false, err
	}

	if !token.Valid {
		return claims, false, nil
	}

	now := p.clock.Now()
	if (!claims.ExpiresAt.IsZero() && now.After(claims.ExpiresAt.Time)) ||
		(!claims.NotBefore.IsZero() && now.Before(claims.NotBefore.Time)) ||
		(claims.Issuer != "" && claims.Issuer != p.issuer) {
		return claims, false, nil
	}

	return claims, true, nil
}

func (p *Processor) RevokeToken(tokenString string) error {
	if p.closed.Load() {
		return ErrProcessorClosed
	}

	if tokenString == "" {
		return ErrEmptyToken
	}

	return p.blacklistManager.BlacklistTokenString(tokenString)
}

func (p *Processor) IsTokenRevoked(tokenString string) (bool, error) {
	if p.closed.Load() {
		return false, ErrProcessorClosed
	}

	if tokenString == "" {
		return false, ErrEmptyToken
	}

	type idClaims struct {
		ID string `json:"jti,omitempty"`
	}

	claims := &idClaims{}
	_, _, err := internal.ParseUnverified(tokenString, claims)
	if err != nil {
		return false, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims.ID == "" {
		return false, ErrTokenMissingID
	}

	return p.blacklistManager.IsBlacklisted(claims.ID)
}
