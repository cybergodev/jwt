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
		// Use rate limit configuration from config if available
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

// CreateTokenWithContext creates a JWT token with context support
func (p *Processor) CreateTokenWithContext(ctx context.Context, claims Claims) (string, error) {
	//  Comprehensive claims validation to prevent attacks
	if err := validateClaimsSecurely(&claims); err != nil {
		return "", fmt.Errorf("claims security validation failed: %w", err)
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

// ValidateTokenWithContext validates a JWT token with context support
func (p *Processor) ValidateTokenWithContext(ctx context.Context, tokenString string) (*Claims, bool, error) {
	// Basic token structure validation
	if strings.Count(tokenString, ".") != 2 {
		return nil, false, ErrInvalidToken
	}

	// Comprehensive token validation to prevent attacks
	if tokenString == "" {
		return nil, false, ErrEmptyToken
	}

	// Check for malicious token patterns
	if containsMaliciousPatterns(tokenString) {
		return nil, false, fmt.Errorf("malicious token pattern detected")
	}

	if err := validateTokenSize(tokenString); err != nil {
		return nil, false, fmt.Errorf("token security validation failed: %w", err)
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
		// Add random delay to prevent timing attacks on error paths
		security.SecureRandomDelay()
		// Return generic error to prevent information leakage
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

	// Create new access token with the same claims but fresh timestamps
	newClaims := *tokenInfo.claims

	// Clear time fields to get fresh ones
	newClaims.IssuedAt = NumericDate{}
	newClaims.ExpiresAt = NumericDate{}
	newClaims.ID = "" // Generate new token ID

	// Create new access token using AccessTokenTTL
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

	// Close rate limiter
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
	if !p.closed {
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

	// Check rate limiting
	if p.rateLimiter != nil && p.rateLimiter.IsRateLimited("token_creation", claims.UserID) {
		return "", ErrRateLimitExceeded
	}

	if err := validateClaimsData(claims); err != nil {
		return "", fmt.Errorf("invalid claims data: %w", err)
	}

	// Use pooled claims for better performance
	claimsCopy := getClaims()
	defer putClaims(claimsCopy)

	// Copy claims efficiently - only copy necessary fields
	claimsCopy.UserID = claims.UserID
	claimsCopy.Username = claims.Username
	claimsCopy.Role = claims.Role
	claimsCopy.SessionID = claims.SessionID
	claimsCopy.ClientID = claims.ClientID

	// Copy slices efficiently
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

	// Copy map efficiently
	if len(claims.Extra) > 0 {
		for k, v := range claims.Extra {
			claimsCopy.Extra[k] = v
		}
	}

	// Copy registered claims
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

// createRefreshTokenWithClaims creates a refresh token with longer TTL (internal use only)
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

// validateTokenInternal validates a JWT token and returns token information (internal use only)
func (p *Processor) validateTokenInternal(tokenString string) (*tokenInfo, error) {
	claims := getClaims()

	token, err := core.ParseWithClaims(tokenString, claims, func(token *core.Core) (any, error) {
		alg, ok := token.Header["alg"].(string)
		if !ok {
			return nil, fmt.Errorf("missing algorithm in token header")
		}

		expectedAlg := string(p.signingMethod)
		if alg != expectedAlg {
			return nil, fmt.Errorf("algorithm mismatch: expected %s, got %s", expectedAlg, alg)
		}

		return p.secretKey.Bytes(), nil
	})

	if err != nil {
		putClaims(claims)
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	now := time.Now()
	valid := token.Valid

	// Time comparisons with proper precision handling
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

// validateClaimsData validates claims data for security issues (internal use only)
func validateClaimsData(claims Claims) error {
	// Check for excessively long string fields to prevent DoS
	const maxStringLength = 1024

	if len(claims.UserID) > maxStringLength {
		return fmt.Errorf("UserID too long: maximum %d characters", maxStringLength)
	}
	if len(claims.Username) > maxStringLength {
		return fmt.Errorf("Username too long: maximum %d characters", maxStringLength)
	}
	if len(claims.Role) > maxStringLength {
		return fmt.Errorf("Role too long: maximum %d characters", maxStringLength)
	}
	if len(claims.SessionID) > maxStringLength {
		return fmt.Errorf("SessionID too long: maximum %d characters", maxStringLength)
	}
	if len(claims.ClientID) > maxStringLength {
		return fmt.Errorf("ClientID too long: maximum %d characters", maxStringLength)
	}
	if len(claims.Issuer) > maxStringLength {
		return fmt.Errorf("Issuer too long: maximum %d characters", maxStringLength)
	}
	if len(claims.Subject) > maxStringLength {
		return fmt.Errorf("Subject too long: maximum %d characters", maxStringLength)
	}
	if len(claims.ID) > maxStringLength {
		return fmt.Errorf("ID too long: maximum %d characters", maxStringLength)
	}

	// Check array sizes to prevent DoS
	const maxArraySize = 100
	if len(claims.Permissions) > maxArraySize {
		return fmt.Errorf("too many permissions: maximum %d allowed", maxArraySize)
	}
	if len(claims.Scopes) > maxArraySize {
		return fmt.Errorf("too many scopes: maximum %d allowed", maxArraySize)
	}
	if len(claims.Audience) > maxArraySize {
		return fmt.Errorf("too many audiences: maximum %d allowed", maxArraySize)
	}

	// Check individual array elements
	for _, perm := range claims.Permissions {
		if len(perm) > maxStringLength {
			return fmt.Errorf("permission too long: maximum %d characters", maxStringLength)
		}
	}
	for _, scope := range claims.Scopes {
		if len(scope) > maxStringLength {
			return fmt.Errorf("scope too long: maximum %d characters", maxStringLength)
		}
	}
	for _, aud := range claims.Audience {
		if len(aud) > maxStringLength {
			return fmt.Errorf("audience too long: maximum %d characters", maxStringLength)
		}
	}

	// Check Extra map size and content
	const maxExtraSize = 50
	if len(claims.Extra) > maxExtraSize {
		return fmt.Errorf("too many extra claims: maximum %d allowed", maxExtraSize)
	}

	for key, value := range claims.Extra {
		if len(key) > maxStringLength {
			return fmt.Errorf("extra claim key too long: maximum %d characters", maxStringLength)
		}
		if str, ok := value.(string); ok && len(str) > maxStringLength {
			return fmt.Errorf("extra claim value too long: maximum %d characters", maxStringLength)
		}
	}

	return nil
}

// getSigningMethod returns the signing method for the given algorithm (internal use only)
func getSigningMethod(method SigningMethod) (signing.Method, error) {
	return signing.GetInternalSigningMethod(string(method))
}

// deepCopyClaims creates an optimized deep copy of claims using object pool
func deepCopyClaims(src *Claims) *Claims {
	if src == nil {
		return nil
	}

	// Use object pool for better performance
	dst := getClaims()

	// Copy simple string fields
	dst.UserID = src.UserID
	dst.Username = src.Username
	dst.Role = src.Role
	dst.SessionID = src.SessionID
	dst.ClientID = src.ClientID

	// Copy registered claims
	dst.Issuer = src.Issuer
	dst.Subject = src.Subject
	dst.ExpiresAt = src.ExpiresAt
	dst.NotBefore = src.NotBefore
	dst.IssuedAt = src.IssuedAt
	dst.ID = src.ID

	// Efficiently copy slices using append for better performance
	if len(src.Permissions) > 0 {
		dst.Permissions = append(dst.Permissions[:0], src.Permissions...)
	}

	if len(src.Scopes) > 0 {
		dst.Scopes = append(dst.Scopes[:0], src.Scopes...)
	}

	if len(src.Audience) > 0 {
		dst.Audience = append(dst.Audience[:0], src.Audience...)
	}

	// Copy map efficiently
	if len(src.Extra) > 0 {
		if dst.Extra == nil {
			dst.Extra = make(map[string]any, len(src.Extra))
		} else {
			clear(dst.Extra)
		}
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

	// Parse token to get ID using pooled claims
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

// Comprehensive claims validation to prevent various attacks
func validateClaimsSecurely(claims *Claims) error {
	// Basic validation
	if claims.UserID == "" && claims.Username == "" {
		return ErrInvalidClaims
	}

	// Validate string fields for malicious content
	if err := validateStringField("UserID", claims.UserID); err != nil {
		return err
	}
	if err := validateStringField("Username", claims.Username); err != nil {
		return err
	}
	if err := validateStringField("Role", claims.Role); err != nil {
		return err
	}
	if err := validateStringField("Issuer", claims.Issuer); err != nil {
		return err
	}
	if err := validateStringField("Subject", claims.Subject); err != nil {
		return err
	}
	if err := validateStringField("SessionID", claims.SessionID); err != nil {
		return err
	}
	if err := validateStringField("ClientID", claims.ClientID); err != nil {
		return err
	}

	//  Validate string fields for injection attacks
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
			if err := validateStringFieldSecurely(fieldName, fieldValue); err != nil {
				return err
			}
		}
	}

	//  Validate array fields
	if err := validateStringArraySecurely("Permissions", claims.Permissions); err != nil {
		return err
	}
	if err := validateStringArraySecurely("Scopes", claims.Scopes); err != nil {
		return err
	}
	if err := validateStringArraySecurely("Audience", claims.Audience); err != nil {
		return err
	}

	//  Validate Extra fields for potential attacks
	if err := validateExtraFieldsSecurely(claims.Extra); err != nil {
		return err
	}

	return nil
}

// Validate individual string fields
func validateStringFieldSecurely(fieldName, value string) error {
	const maxFieldLength = 256
	if len(value) > maxFieldLength {
		return fmt.Errorf("field %s too long: maximum %d characters allowed", fieldName, maxFieldLength)
	}

	// Check for null bytes and control characters
	for i, char := range value {
		if char == 0 {
			return fmt.Errorf("field %s contains null byte at position %d", fieldName, i)
		}
		if char < 32 && char != 9 && char != 10 && char != 13 {
			return fmt.Errorf("field %s contains control character at position %d", fieldName, i)
		}
	}

	// Check for potential injection patterns
	suspiciousPatterns := []string{
		"<script", "</script", "javascript:", "data:", "eval(", "alert(",
		"onload=", "onerror=", "onclick=", "../", "..\\", "file://",
		"document.", "window.", "http://", "https://", "vbscript:",
	}

	lowerValue := strings.ToLower(value)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerValue, pattern) {
			return fmt.Errorf("field %s contains suspicious pattern: %s", fieldName, pattern)
		}
	}

	return nil
}

// Validate string arrays
func validateStringArraySecurely(fieldName string, values []string) error {
	const maxArrayLength = 100
	if len(values) > maxArrayLength {
		return fmt.Errorf("field %s array too long: maximum %d items allowed", fieldName, maxArrayLength)
	}

	for i, value := range values {
		if err := validateStringFieldSecurely(fmt.Sprintf("%s[%d]", fieldName, i), value); err != nil {
			return err
		}
	}

	return nil
}

// Validate Extra fields map
func validateExtraFieldsSecurely(extra map[string]any) error {
	const maxExtraFields = 50
	if len(extra) > maxExtraFields {
		return fmt.Errorf("too many extra fields: maximum %d allowed", maxExtraFields)
	}

	for key, value := range extra {
		// Validate key
		if err := validateStringFieldSecurely("extra_key", key); err != nil {
			return fmt.Errorf("invalid extra field key: %w", err)
		}

		// Validate value based on type
		switch v := value.(type) {
		case string:
			if err := validateStringFieldSecurely("extra_value", v); err != nil {
				return fmt.Errorf("invalid extra field value for key %s: %w", key, err)
			}
		case []string:
			if err := validateStringArraySecurely("extra_array", v); err != nil {
				return fmt.Errorf("invalid extra field array for key %s: %w", key, err)
			}
		case map[string]any:
			// Prevent nested maps to avoid complexity attacks
			return fmt.Errorf("nested maps not allowed in extra fields for security")
		}
	}

	return nil
}

// validateTokenSize validates token size for security
func validateTokenSize(tokenString string) error {
	const maxSecureTokenSize = 8192 // 8KB max token size

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

// containsMaliciousPatterns checks for malicious token patterns
func containsMaliciousPatterns(token string) bool {
	// Check for excessively long tokens (potential DoS)
	if len(token) > 16384 { // 16KB limit
		return true
	}

	// Check for null bytes (potential injection)
	if strings.Contains(token, "\x00") {
		return true
	}

	// Check for control characters that shouldn't be in JWT
	for _, char := range token {
		if char < 32 && char != 9 && char != 10 && char != 13 { // Allow tab, LF, CR
			return true
		}
	}

	// Check for suspicious patterns that might indicate tampering
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



	// Check for repeated patterns that might indicate algorithmic attacks
	if len(token) > 1000 {
		// Optimized check for repeated substrings - only check a few samples
		step := len(token) / 10 // Check 10 samples across the token
		if step < 100 {
			step = 100
		}
		for i := 0; i < len(token)-100; i += step {
			end := i + 100
			if end > len(token) {
				break
			}
			substr := token[i:end]
			// Use a more efficient counting method
			if countSubstring(token, substr) > 3 {
				return true
			}
		}
	}

	return false
}

// validateStringField validates individual string fields for security
func validateStringField(fieldName, value string) error {
	if value == "" {
		return nil // Empty values are allowed
	}

	// Check maximum length to prevent DoS
	const maxFieldLength = 1024
	if len(value) > maxFieldLength {
		return fmt.Errorf("field %s too long: maximum %d characters allowed", fieldName, maxFieldLength)
	}

	// Check for null bytes
	if strings.Contains(value, "\x00") {
		return fmt.Errorf("field %s contains null bytes", fieldName)
	}

	// Check for control characters (except common whitespace)
	for i, char := range value {
		if char < 32 && char != 9 && char != 10 && char != 13 { // Allow tab, LF, CR
			return fmt.Errorf("field %s contains invalid control character at position %d", fieldName, i)
		}
	}

	// Check for potentially dangerous patterns
	dangerousPatterns := []string{
		"<script", "javascript:", "data:", "vbscript:",
		"onload=", "onerror=", "eval(", "alert(",
		"document.", "window.", "location.",
		"../", "..\\", "file://",
	}

	lowerValue := strings.ToLower(value)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerValue, pattern) {
			return fmt.Errorf("field %s contains potentially dangerous pattern: %s", fieldName, pattern)
		}
	}

	return nil
}

// countSubstring counts occurrences of substr in s with early termination
func countSubstring(s, substr string) int {
	count := 0
	start := 0
	for {
		pos := strings.Index(s[start:], substr)
		if pos == -1 {
			break
		}
		count++
		if count > 3 { // Early termination for performance
			return count
		}
		start += pos + 1
	}
	return count
}
