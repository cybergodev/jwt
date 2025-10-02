package jwt

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/cybergodev/jwt/internal/blacklist"
	"github.com/cybergodev/jwt/internal/core"
	"github.com/cybergodev/jwt/internal/security"
	"github.com/cybergodev/jwt/internal/signing"
)

var (
	ErrManagerClosed = errors.New("manager is closed")
)

type Processor struct {
	secretKey        *security.SecureBytes
	accessTokenTTL   time.Duration
	refreshTokenTTL  time.Duration
	issuer           string
	signingMethod    SigningMethod
	blacklistManager blacklist.Manager
	rateLimiter      *SecurityRateLimiter

	mu     sync.RWMutex
	closed bool
}

// New creates a new JWT Processor with secretKey and optional configuration
func New(secretKey string, config ...Config) (*Processor, error) {
	if len(secretKey) < 32 {
		return nil, ErrInvalidSecretKey
	}
	return NewWithBlacklist(secretKey, DefaultBlacklistConfig(), config...)
}

// NewWithBlacklist creates a new JWT Processor with custom blacklist configuration
func NewWithBlacklist(secretKey string, blacklistConfig BlacklistConfig, config ...Config) (*Processor, error) {
	if len(secretKey) < 32 {
		return nil, ErrInvalidSecretKey
	}

	var cfg Config
	if len(config) > 0 {
		cfg = config[0]
	} else {
		cfg = DefaultConfig()
	}

	cfg.SecretKey = secretKey

	if cfg.SigningMethod == "" {
		cfg.SigningMethod = SigningMethodHS256
	}

	if cfg.Issuer == "" {
		cfg.Issuer = "jwt-service"
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	secureKey := security.NewSecureBytesFromSlice([]byte(cfg.SecretKey))

	internalConfig := blacklist.Config{
		CleanupInterval:   blacklistConfig.CleanupInterval,
		MaxSize:           blacklistConfig.MaxSize,
		EnableAutoCleanup: blacklistConfig.EnableAutoCleanup,
		StoreType:         blacklistConfig.StoreType,
	}
	store := blacklist.NewStore(internalConfig)
	blacklistMgr := blacklist.NewManager(store, internalConfig)

	var rateLimiter *SecurityRateLimiter
	if cfg.EnableRateLimit {
		if cfg.RateLimit != nil {
			rateLimiter = NewSecurityRateLimiterWithConfig(*cfg.RateLimit)
		} else {
			rateLimiter = NewSecurityRateLimiter()
		}
	}

	processor := &Processor{
		secretKey:        secureKey,
		accessTokenTTL:   cfg.AccessTokenTTL,
		refreshTokenTTL:  cfg.RefreshTokenTTL,
		issuer:           cfg.Issuer,
		signingMethod:    cfg.SigningMethod,
		blacklistManager: blacklistMgr,
		rateLimiter:      rateLimiter,
	}

	runtime.SetFinalizer(processor, (*Processor).finalize)
	return processor, nil
}

// CreateToken creates a JWT token with the provided claims
func (p *Processor) CreateToken(claims Claims) (string, error) {
	return p.CreateTokenWithContext(context.Background(), claims)
}

func (p *Processor) CreateTokenWithContext(ctx context.Context, claims Claims) (string, error) {
	if err := validateClaims(&claims); err != nil {
		return "", fmt.Errorf("claims validation failed: %w", err)
	}

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if err := p.checkClosed(); err != nil {
		return "", err
	}

	return p.createTokenWithClaims(claims)
}

// ValidateToken validates a JWT token and returns the claims with automatic cleanup
func (p *Processor) ValidateToken(tokenString string) (*Claims, bool, error) {
	return p.ValidateTokenWithContext(context.Background(), tokenString)
}

func (p *Processor) ValidateTokenWithContext(ctx context.Context, tokenString string) (*Claims, bool, error) {
	if err := validateTokenSize(tokenString); err != nil {
		return nil, false, err
	}

	if containsMaliciousPatterns(tokenString) {
		return nil, false, ErrInvalidToken
	}

	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	default:
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if err := p.checkClosed(); err != nil {
		return nil, false, err
	}

	tokInfo, err := p.validateTokenInternal(tokenString)
	if err != nil {
		security.SecureRandomDelay()
		return nil, false, ErrInvalidToken
	}
	defer tokInfo.cleanup()

	if tokInfo.claims.ID != "" {
		isBlacklisted, err := p.blacklistManager.IsBlacklisted(tokInfo.claims.ID)
		if err != nil {
			return nil, false, fmt.Errorf("blacklist check failed: %w", err)
		}
		if isBlacklisted {
			return nil, false, fmt.Errorf("token has been revoked")
		}
	}

	claimsCopy := deepCopyClaims(tokInfo.claims)

	return claimsCopy, tokInfo.valid, nil
}

// CreateRefreshToken creates a refresh token with longer TTL using RefreshTokenTTL
func (p *Processor) CreateRefreshToken(claims Claims) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if err := p.checkClosed(); err != nil {
		return "", err
	}

	return p.createRefreshTokenWithClaims(claims)
}

// RefreshToken validates an existing token and creates a new access token if valid
func (p *Processor) RefreshToken(refreshTokenString string) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if err := p.checkClosed(); err != nil {
		return "", err
	}

	tokenInfo, err := p.validateTokenInternal(refreshTokenString)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}
	defer tokenInfo.cleanup()

	if !tokenInfo.valid {
		return "", fmt.Errorf("refresh token is not valid")
	}

	newClaims := *tokenInfo.claims
	newClaims.IssuedAt = NumericDate{}
	newClaims.ExpiresAt = NumericDate{}
	newClaims.ID = ""

	return p.createTokenWithClaims(newClaims)
}

// Close gracefully shuts down the processor and securely clears the secret key
func (p *Processor) Close() error {
	return p.CloseWithContext(context.Background())
}

// CloseWithContext gracefully shuts down the processor with context support
func (p *Processor) CloseWithContext(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return ErrManagerClosed
	}

	var closeErr error

	if p.blacklistManager != nil {
		done := make(chan error, 1)
		go func() {
			done <- p.blacklistManager.Close()
		}()

		select {
		case err := <-done:
			if err != nil {
				closeErr = fmt.Errorf("blacklist manager close failed: %w", err)
			}
		case <-ctx.Done():
			closeErr = fmt.Errorf("blacklist manager close timeout: %w", ctx.Err())
		}
	}

	if p.secretKey != nil {
		p.secretKey.Destroy()
		p.secretKey = nil
	}

	if p.rateLimiter != nil {
		p.rateLimiter.Close()
		p.rateLimiter = nil
	}

	p.closed = true
	runtime.SetFinalizer(p, nil)
	return closeErr
}

// finalize is called by the garbage collector to ensure resources are cleaned up
func (p *Processor) finalize() {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()

	if !closed {
		p.Close()
	}
}

func (p *Processor) checkClosed() error {
	if p.closed {
		return ErrManagerClosed
	}
	return nil
}

// IsClosed returns true if the processor has been closed
func (p *Processor) IsClosed() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.closed
}

func (p *Processor) createTokenWithClaims(claims Claims) (string, error) {
	if err := p.checkClosed(); err != nil {
		return "", err
	}

	if p.rateLimiter != nil && p.rateLimiter.IsRateLimited("token_creation", claims.UserID) {
		return "", ErrRateLimitExceeded
	}

	claimsCopy := getClaims()
	defer putClaims(claimsCopy)

	claimsCopy.UserID = claims.UserID
	claimsCopy.Username = claims.Username
	claimsCopy.Role = claims.Role
	claimsCopy.SessionID = claims.SessionID
	claimsCopy.ClientID = claims.ClientID

	if len(claims.Permissions) > 0 {
		claimsCopy.Permissions = claimsCopy.Permissions[:0]
		claimsCopy.Permissions = append(claimsCopy.Permissions, claims.Permissions...)
	}
	if len(claims.Scopes) > 0 {
		claimsCopy.Scopes = claimsCopy.Scopes[:0]
		claimsCopy.Scopes = append(claimsCopy.Scopes, claims.Scopes...)
	}
	if len(claims.Audience) > 0 {
		claimsCopy.Audience = claimsCopy.Audience[:0]
		claimsCopy.Audience = append(claimsCopy.Audience, claims.Audience...)
	}

	if len(claims.Extra) > 0 {
		if claimsCopy.Extra == nil {
			claimsCopy.Extra = make(map[string]any, len(claims.Extra))
		}
		for k, v := range claims.Extra {
			claimsCopy.Extra[k] = v
		}
	}

	claimsCopy.Issuer = claims.Issuer
	claimsCopy.Subject = claims.Subject
	claimsCopy.ExpiresAt = claims.ExpiresAt
	claimsCopy.NotBefore = claims.NotBefore
	claimsCopy.IssuedAt = claims.IssuedAt
	claimsCopy.ID = claims.ID

	now := time.Now()
	if claimsCopy.IssuedAt.IsZero() {
		claimsCopy.IssuedAt = NewNumericDate(now)
	}
	if claimsCopy.ExpiresAt.IsZero() {
		claimsCopy.ExpiresAt = NewNumericDate(now.Add(p.accessTokenTTL))
	}
	if claimsCopy.Issuer == "" {
		claimsCopy.Issuer = p.issuer
	}
	if claimsCopy.ID == "" {
		claimsCopy.ID = core.GenerateTokenIDFast()
	}

	signingMethod, err := getSigningMethod(p.signingMethod)
	if err != nil {
		return "", fmt.Errorf("failed to get signing method: %w", err)
	}

	token := core.NewTokenWithClaims(signingMethod, claimsCopy)
	tokenString, err := token.SignedString(p.secretKey.Bytes())
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

func (p *Processor) createRefreshTokenWithClaims(claims Claims) (string, error) {
	if err := p.checkClosed(); err != nil {
		return "", err
	}

	claimsCopy := claims

	now := time.Now()
	if claimsCopy.IssuedAt.IsZero() {
		claimsCopy.IssuedAt = NewNumericDate(now)
	}
	if claimsCopy.ExpiresAt.IsZero() {
		claimsCopy.ExpiresAt = NewNumericDate(now.Add(p.refreshTokenTTL))
	}
	if claimsCopy.Issuer == "" {
		claimsCopy.Issuer = p.issuer
	}
	if claimsCopy.ID == "" {
		claimsCopy.ID = core.GenerateTokenIDFast()
	}

	signingMethod, err := getSigningMethod(p.signingMethod)
	if err != nil {
		return "", fmt.Errorf("failed to get signing method: %w", err)
	}

	token := core.NewTokenWithClaims(signingMethod, &claimsCopy)
	tokenString, err := token.SignedString(p.secretKey.Bytes())
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

func (p *Processor) validateTokenInternal(tokenString string) (*tokenInfo, error) {
	claims := getClaims()

	token, err := core.ParseWithClaims(tokenString, claims, func(token *core.Core) (any, error) {
		alg, ok := token.Header["alg"].(string)
		if !ok {
			return nil, ErrInvalidToken
		}

		expectedAlg := string(p.signingMethod)
		if alg != expectedAlg {
			return nil, ErrInvalidToken
		}

		return p.secretKey.Bytes(), nil
	})

	if err != nil {
		putClaims(claims)
		return nil, ErrInvalidToken
	}

	now := time.Now()
	valid := token.Valid

	if !claims.ExpiresAt.IsZero() && now.After(claims.ExpiresAt.Time) {
		valid = false
	}

	if !claims.NotBefore.IsZero() && now.Before(claims.NotBefore.Time) {
		valid = false
	}

	if claims.Issuer != p.issuer {
		valid = false
	}

	info := getTokenInfo()
	info.claims = claims
	info.valid = valid
	info.expiresAt = claims.ExpiresAt.Time
	info.issuedAt = claims.IssuedAt.Time
	info.tokenID = claims.ID
	info.algorithm = string(p.signingMethod)

	return info, nil
}

func validateClaims(claims *Claims) error {
	if claims.UserID == "" && claims.Username == "" {
		return ErrInvalidClaims
	}

	const maxStringLength = 256
	const maxArraySize = 100
	const maxExtraSize = 50

	stringFields := map[string]string{
		"UserID":    claims.UserID,
		"Username":  claims.Username,
		"Role":      claims.Role,
		"SessionID": claims.SessionID,
		"ClientID":  claims.ClientID,
		"Issuer":    claims.Issuer,
		"Subject":   claims.Subject,
		"ID":        claims.ID,
	}

	for fieldName, fieldValue := range stringFields {
		if fieldValue != "" {
			if err := validateField(fieldName, fieldValue, maxStringLength); err != nil {
				return err
			}
		}
	}

	if len(claims.Permissions) > maxArraySize {
		return fmt.Errorf("too many permissions: maximum %d allowed", maxArraySize)
	}
	if len(claims.Scopes) > maxArraySize {
		return fmt.Errorf("too many scopes: maximum %d allowed", maxArraySize)
	}
	if len(claims.Audience) > maxArraySize {
		return fmt.Errorf("too many audiences: maximum %d allowed", maxArraySize)
	}

	for _, perm := range claims.Permissions {
		if err := validateField("permission", perm, maxStringLength); err != nil {
			return err
		}
	}
	for _, scope := range claims.Scopes {
		if err := validateField("scope", scope, maxStringLength); err != nil {
			return err
		}
	}
	for _, aud := range claims.Audience {
		if err := validateField("audience", aud, maxStringLength); err != nil {
			return err
		}
	}

	if len(claims.Extra) > maxExtraSize {
		return fmt.Errorf("too many extra claims: maximum %d allowed", maxExtraSize)
	}

	for key, value := range claims.Extra {
		if err := validateField("extra_key", key, maxStringLength); err != nil {
			return fmt.Errorf("invalid extra field key: %w", err)
		}
		switch v := value.(type) {
		case string:
			if err := validateField("extra_value", v, maxStringLength); err != nil {
				return fmt.Errorf("invalid extra field value for key %s: %w", key, err)
			}
		case []string:
			for _, item := range v {
				if err := validateField("extra_array_item", item, maxStringLength); err != nil {
					return fmt.Errorf("invalid extra field array for key %s: %w", key, err)
				}
			}
		case map[string]any:
			return fmt.Errorf("nested maps not allowed in extra fields")
		}
	}

	return nil
}

func validateField(fieldName, value string, maxLength int) error {
	if len(value) > maxLength {
		return fmt.Errorf("field %s too long: maximum %d characters", fieldName, maxLength)
	}

	for i, char := range value {
		if char == 0 {
			return fmt.Errorf("field %s contains null byte at position %d", fieldName, i)
		}
		if char < 32 && char != 9 && char != 10 && char != 13 {
			return fmt.Errorf("field %s contains control character at position %d", fieldName, i)
		}
	}

	suspiciousPatterns := []string{
		"<script", "</script", "javascript:", "data:", "eval(", "alert(",
		"onload=", "onerror=", "onclick=", "../", "..\\", "file://",
		"document.", "window.", "vbscript:", "http://", "https://",
	}

	lowerValue := strings.ToLower(value)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerValue, pattern) {
			return fmt.Errorf("field %s contains suspicious pattern", fieldName)
		}
	}

	return nil
}

func getSigningMethod(method SigningMethod) (signing.Method, error) {
	return signing.GetInternalSigningMethod(string(method))
}

func deepCopyClaims(src *Claims) *Claims {
	if src == nil {
		return nil
	}

	dst := &Claims{
		UserID:    src.UserID,
		Username:  src.Username,
		Role:      src.Role,
		SessionID: src.SessionID,
		ClientID:  src.ClientID,
		RegisteredClaims: RegisteredClaims{
			Issuer:    src.Issuer,
			Subject:   src.Subject,
			ExpiresAt: src.ExpiresAt,
			NotBefore: src.NotBefore,
			IssuedAt:  src.IssuedAt,
			ID:        src.ID,
		},
	}

	if len(src.Permissions) > 0 {
		dst.Permissions = make([]string, len(src.Permissions))
		copy(dst.Permissions, src.Permissions)
	}

	if len(src.Scopes) > 0 {
		dst.Scopes = make([]string, len(src.Scopes))
		copy(dst.Scopes, src.Scopes)
	}

	if len(src.Audience) > 0 {
		dst.Audience = make([]string, len(src.Audience))
		copy(dst.Audience, src.Audience)
	}

	if len(src.Extra) > 0 {
		dst.Extra = make(map[string]any, len(src.Extra))
		for k, v := range src.Extra {
			dst.Extra[k] = v
		}
	}

	return dst
}

// RevokeToken adds a token to the blacklist, preventing its future use
func (p *Processor) RevokeToken(tokenString string) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if err := p.checkClosed(); err != nil {
		return err
	}

	return p.blacklistManager.BlacklistTokenString(tokenString)
}

// RevokeTokenByID adds a token ID to the blacklist with specified expiration
func (p *Processor) RevokeTokenByID(tokenID string, expiresAt time.Time) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if err := p.checkClosed(); err != nil {
		return err
	}

	return p.blacklistManager.BlacklistToken(tokenID, expiresAt)
}

// IsTokenRevoked checks if a token is in the blacklist
func (p *Processor) IsTokenRevoked(tokenString string) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if err := p.checkClosed(); err != nil {
		return false, err
	}

	claims := getClaims()
	defer putClaims(claims)

	_, _, err := core.ParseUnverified(tokenString, claims)
	if err != nil {
		return false, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims.ID == "" {
		return false, fmt.Errorf("token does not contain a valid ID")
	}

	return p.blacklistManager.IsBlacklisted(claims.ID)
}

func validateTokenSize(tokenString string) error {
	const maxSecureTokenSize = 8192

	if len(tokenString) == 0 {
		return ErrEmptyToken
	}

	if len(tokenString) > maxSecureTokenSize {
		return fmt.Errorf("token too large")
	}

	if strings.Count(tokenString, ".") != 2 {
		return ErrInvalidToken
	}

	return nil
}

func containsMaliciousPatterns(token string) bool {
	if len(token) > 16384 {
		return true
	}

	if strings.Contains(token, "\x00") {
		return true
	}

	for _, char := range token {
		if char < 32 && char != 9 && char != 10 && char != 13 {
			return true
		}
	}

	suspiciousPatterns := []string{
		"<script", "javascript:", "data:", "vbscript:",
		"onload=", "onerror=", "eval(", "alert(",
		"document.", "window.", "location.",
		"../", "..\\", "file://", "http://",
	}

	lowerToken := strings.ToLower(token)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerToken, pattern) {
			return true
		}
	}

	return false
}
