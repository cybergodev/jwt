package jwt

import (
	"fmt"
	"maps"
	"sync/atomic"
	"time"

	"github.com/cybergodev/jwt/internal/blacklist"
	"github.com/cybergodev/jwt/internal/core"
	"github.com/cybergodev/jwt/internal/security"
	"github.com/cybergodev/jwt/internal/signing"
)

type Processor struct {
	secretKey        []byte
	accessTokenTTL   time.Duration
	refreshTokenTTL  time.Duration
	issuer           string
	signingMethod    SigningMethod
	blacklistManager *blacklist.Manager
	rateLimiter      *RateLimiter
	closed           atomic.Bool
}

// New creates a new JWT Processor with secretKey and optional configuration.
// The processor is thread-safe and can be used concurrently by multiple goroutines.
// Always call Close() when done to release resources and securely clear the secret key.
func New(secretKey string, config ...Config) (*Processor, error) {
	return newProcessor(secretKey, DefaultBlacklistConfig(), config...)
}

// NewWithBlacklist creates a new JWT Processor with custom blacklist configuration.
// Use this when you need fine-grained control over token revocation behavior.
// The processor is thread-safe and can be used concurrently by multiple goroutines.
// Always call Close() when done to release resources and securely clear the secret key.
func NewWithBlacklist(secretKey string, blacklistConfig BlacklistConfig, config ...Config) (*Processor, error) {
	return newProcessor(secretKey, blacklistConfig, config...)
}

func newProcessor(secretKey string, blacklistConfig BlacklistConfig, config ...Config) (*Processor, error) {
	if blacklistConfig.MaxSize <= 0 {
		return nil, fmt.Errorf("%w: blacklist max size must be positive", ErrInvalidConfig)
	}
	if blacklistConfig.CleanupInterval <= 0 {
		return nil, fmt.Errorf("%w: blacklist cleanup interval must be positive", ErrInvalidConfig)
	}

	var cfg Config
	if len(config) > 0 {
		cfg = config[0]
		cfg.SecretKey = secretKey
	} else {
		cfg = DefaultConfig()
		cfg.SecretKey = secretKey
	}

	if cfg.SigningMethod == "" {
		cfg.SigningMethod = SigningMethodHS256
	}

	if cfg.Issuer == "" {
		cfg.Issuer = "jwt-service"
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	secretKeyBytes := make([]byte, len(cfg.SecretKey))
	copy(secretKeyBytes, cfg.SecretKey)

	store := blacklist.NewStore(blacklist.Config{
		CleanupInterval:   blacklistConfig.CleanupInterval,
		MaxSize:           blacklistConfig.MaxSize,
		EnableAutoCleanup: blacklistConfig.EnableAutoCleanup,
	})
	blacklistMgr := blacklist.NewManager(store)

	var rateLimiter *RateLimiter
	if cfg.RateLimiter != nil {
		rateLimiter = cfg.RateLimiter
	} else if cfg.EnableRateLimit {
		rate := cfg.RateLimitRate
		window := cfg.RateLimitWindow
		if rate <= 0 {
			rate = 100
		}
		if window <= 0 {
			window = time.Minute
		}
		rateLimiter = NewRateLimiter(rate, window)
	}

	processor := &Processor{
		secretKey:        secretKeyBytes,
		accessTokenTTL:   cfg.AccessTokenTTL,
		refreshTokenTTL:  cfg.RefreshTokenTTL,
		issuer:           cfg.Issuer,
		signingMethod:    cfg.SigningMethod,
		blacklistManager: blacklistMgr,
		rateLimiter:      rateLimiter,
	}

	return processor, nil
}

// CreateToken creates a JWT access token with the provided claims.
// The token will be signed using the processor's configured signing method.
// Returns an error if the processor is closed, claims are invalid, or rate limit is exceeded.
func (p *Processor) CreateToken(claims Claims) (string, error) {
	if p.closed.Load() {
		return "", ErrProcessorClosed
	}

	if err := validateClaims(&claims); err != nil {
		return "", err
	}

	return p.createTokenWithClaims(claims)
}

// ValidateToken validates a JWT token and returns the claims.
// Returns the claims, a boolean indicating validity, and an error if validation fails.
// The boolean is false if the token is expired, not yet valid, or has an invalid issuer.
// Returns ErrTokenRevoked if the token has been blacklisted.
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
		return Claims{}, false, ErrInvalidToken
	}

	if !valid {
		putClaims(claims)
		return Claims{}, false, nil
	}

	if claims.ID != "" {
		isBlacklisted, err := p.blacklistManager.IsBlacklisted(claims.ID)
		if err != nil {
			putClaims(claims)
			return Claims{}, false, err
		}
		if isBlacklisted {
			putClaims(claims)
			return Claims{}, false, ErrTokenRevoked
		}
	}

	result := *claims
	putClaims(claims)
	return result, valid, nil
}

// CreateRefreshToken creates a refresh token with longer TTL.
// Refresh tokens are used to obtain new access tokens without re-authentication.
// Returns an error if the processor is closed, claims are invalid, or rate limit is exceeded.
func (p *Processor) CreateRefreshToken(claims Claims) (string, error) {
	if p.closed.Load() {
		return "", ErrProcessorClosed
	}

	if err := validateClaims(&claims); err != nil {
		return "", err
	}

	return p.createTokenWithTTL(claims, p.refreshTokenTTL)
}

// RefreshToken validates a refresh token and creates a new access token.
// The new access token will have the same claims as the refresh token but with a new expiration time.
// Returns an error if the refresh token is invalid, expired, or the processor is closed.
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

	return p.createTokenWithClaims(newClaims)
}

// Close gracefully shuts down the processor and securely clears the secret key.
// This method should always be called when the processor is no longer needed.
// After calling Close, all subsequent operations will return ErrProcessorClosed.
// It is safe to call Close multiple times.
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
		security.ZeroBytes(p.secretKey)
	}

	return closeErr
}

// IsClosed returns true if the processor has been closed
func (p *Processor) IsClosed() bool {
	return p.closed.Load()
}

func (p *Processor) createTokenWithClaims(claims Claims) (string, error) {
	return p.createTokenWithTTL(claims, p.accessTokenTTL)
}

func (p *Processor) createTokenWithTTL(claims Claims, ttl time.Duration) (string, error) {
	if p.rateLimiter != nil && !p.rateLimiter.Allow(claims.UserID) {
		return "", ErrRateLimitExceeded
	}

	claimsCopy := getClaims()
	defer putClaims(claimsCopy)

	copyClaims(claimsCopy, &claims)

	now := time.Now()
	if claimsCopy.IssuedAt.IsZero() {
		claimsCopy.IssuedAt = NewNumericDate(now)
	}
	if claimsCopy.ExpiresAt.IsZero() {
		claimsCopy.ExpiresAt = NewNumericDate(now.Add(ttl))
	}
	if claimsCopy.Issuer == "" {
		claimsCopy.Issuer = p.issuer
	}
	if claimsCopy.ID == "" {
		claimsCopy.ID = core.GenerateTokenIDFast()
	}

	signingMethod, err := signing.GetInternalSigningMethod(string(p.signingMethod))
	if err != nil {
		return "", err
	}

	token := core.NewTokenWithClaims(signingMethod, claimsCopy)
	return token.SignedString(p.secretKey)
}

func copyClaims(dst, src *Claims) {
	*dst = Claims{
		UserID:      src.UserID,
		Username:    src.Username,
		Role:        src.Role,
		SessionID:   src.SessionID,
		ClientID:    src.ClientID,
		Permissions: append(dst.Permissions[:0], src.Permissions...),
		Scopes:      append(dst.Scopes[:0], src.Scopes...),
		Extra:       dst.Extra,
		RegisteredClaims: RegisteredClaims{
			Issuer:    src.Issuer,
			Subject:   src.Subject,
			Audience:  append(dst.Audience[:0], src.Audience...),
			ExpiresAt: src.ExpiresAt,
			NotBefore: src.NotBefore,
			IssuedAt:  src.IssuedAt,
			ID:        src.ID,
		},
	}

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

	token, err := core.ParseWithClaims(tokenString, claims, func(token *core.Core) (any, error) {
		alg, ok := token.Header["alg"].(string)
		if !ok || alg != string(p.signingMethod) {
			return nil, ErrInvalidToken
		}
		return p.secretKey, nil
	})

	if err != nil {
		return claims, false, err
	}

	if !token.Valid {
		return claims, false, nil
	}

	now := time.Now()
	if !claims.ExpiresAt.IsZero() && now.After(claims.ExpiresAt.Time) {
		return claims, false, nil
	}
	if !claims.NotBefore.IsZero() && now.Before(claims.NotBefore.Time) {
		return claims, false, nil
	}
	if claims.Issuer != p.issuer {
		return claims, false, nil
	}

	return claims, true, nil
}

// RevokeToken adds a token to the blacklist, preventing its future use.
// The token will remain blacklisted until it expires naturally.
// Returns an error if the processor is closed or the token cannot be parsed.
func (p *Processor) RevokeToken(tokenString string) error {
	if p.closed.Load() {
		return ErrProcessorClosed
	}

	if tokenString == "" {
		return ErrEmptyToken
	}

	return p.blacklistManager.BlacklistTokenString(tokenString)
}

// IsTokenRevoked checks if a token has been revoked (is in the blacklist).
// Returns true if the token is blacklisted, false otherwise.
// Returns an error if the processor is closed or the token cannot be parsed.
func (p *Processor) IsTokenRevoked(tokenString string) (bool, error) {
	if p.closed.Load() {
		return false, ErrProcessorClosed
	}

	if tokenString == "" {
		return false, ErrEmptyToken
	}

	type minimalClaims struct {
		ID string `json:"jti,omitempty"`
	}

	claims := &minimalClaims{}

	_, _, err := core.ParseUnverified(tokenString, claims)
	if err != nil {
		return false, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims.ID == "" {
		return false, ErrTokenMissingID
	}

	return p.blacklistManager.IsBlacklisted(claims.ID)
}
