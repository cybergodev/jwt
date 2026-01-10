package jwt

import (
	"fmt"
	"maps"
	"sync/atomic"
	"time"

	"github.com/cybergodev/jwt/internal"
)

type Processor struct {
	secretKey        []byte
	accessTokenTTL   time.Duration
	refreshTokenTTL  time.Duration
	issuer           string
	signingMethod    SigningMethod
	blacklistManager *internal.Manager
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
	} else {
		cfg = DefaultConfig()
	}
	cfg.SecretKey = secretKey

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	secretKeyBytes := make([]byte, len(cfg.SecretKey))
	copy(secretKeyBytes, cfg.SecretKey)

	store := internal.NewMemoryStore(
		blacklistConfig.MaxSize,
		blacklistConfig.CleanupInterval,
		blacklistConfig.EnableAutoCleanup,
	)

	var rateLimiter *RateLimiter
	if cfg.RateLimiter != nil {
		rateLimiter = cfg.RateLimiter
	} else if cfg.EnableRateLimit {
		rateLimiter = NewRateLimiter(cfg.RateLimitRate, cfg.RateLimitWindow)
	}

	return &Processor{
		secretKey:        secretKeyBytes,
		accessTokenTTL:   cfg.AccessTokenTTL,
		refreshTokenTTL:  cfg.RefreshTokenTTL,
		issuer:           cfg.Issuer,
		signingMethod:    cfg.SigningMethod,
		blacklistManager: internal.NewManager(store),
		rateLimiter:      rateLimiter,
	}, nil
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
		if claims != nil {
			putClaims(claims)
		}
		return Claims{}, false, ErrInvalidToken
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
		tokenID, err := internal.GenerateTokenIDFast()
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
	return token.SignedString(p.secretKey)
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
		return p.secretKey, nil
	})

	if err != nil {
		return claims, false, err
	}

	if !token.Valid {
		return claims, false, nil
	}

	now := time.Now()
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
