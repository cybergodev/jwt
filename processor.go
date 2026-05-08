// Package jwt provides a high-performance, thread-safe JWT (JSON Web Token) library
// for Go. It supports HMAC, RSA (PKCS#1v15 and PSS), and ECDSA signing algorithms,
// with built-in token blacklist, rate limiting, and clock injection for testing.
//
// The central type is [Processor], created via [New] with a [Config].
// Use [DefaultConfig] to obtain a configuration with sensible defaults,
// then set SecretKey (HMAC) or SigningKey (asymmetric) before calling [New].
//
// Basic usage:
//
//	cfg := jwt.DefaultConfig()
//	cfg.SecretKey = "your-32-byte-secret-key-here-minimum"
//	p, err := jwt.New(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer p.Close()
//
//	claims := &jwt.Claims{UserID: "user123", Username: "alice"}
//	token, err := p.Create(claims)
package jwt

import (
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cybergodev/jwt/internal"
)

// Processor handles JWT token creation, validation, refresh, and revocation.
// It is the central type in the library, created via New() with a Config.
// All methods are goroutine-safe. Call Close() when done to zero the secret key
// and release pooled resources.
type Processor struct {
	secretKey         []byte // For HMAC algorithms
	asymmetricKey     any    // For RSA/ECDSA algorithms (private key)
	verificationKey   any    // For RSA/ECDSA verification (public key)
	accessTokenTTL    time.Duration
	refreshTokenTTL   time.Duration
	issuer            string
	audience          string
	signingMethod     SigningMethod
	signingMethodImpl internal.Method // Cached at construction to avoid per-call map lookup
	blacklistManager  *internal.Manager
	rateLimiter       RateLimitProvider
	clock             ClockProvider
	isAsymmetric      bool
	closed            atomic.Bool
	mu                sync.RWMutex
}

// New creates a new JWT Processor with the given configuration.
// Use DefaultConfig() to obtain a configuration with sensible defaults,
// then modify fields as needed before passing it to New.
// The processor is thread-safe and can be used concurrently by multiple goroutines.
// Always call Close() when done to release resources and securely clear the secret key.
//
// Returns errors:
//   - [ErrInvalidConfig]: nil config, invalid TTL values, or invalid blacklist config
//   - [ErrInvalidSecretKey]: missing key, key too short (<32 bytes), weak key, wrong key type, or ECDSA curve mismatch
//   - [ErrInvalidSigningMethod]: unrecognized signing method
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
		isAsymmetric:     config.SigningMethod.isAsymmetric(),
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
	// Cache signing method implementation to avoid per-call map lookup.
	// Error safely discarded: Validate() already confirmed SigningMethod is valid.
	p.signingMethodImpl, _ = internal.GetInternalSigningMethod(string(p.signingMethod))

	return p, nil
}

// Create creates a new JWT access token with the given claims.
// Accepts any type implementing CustomClaims, including *Claims for built-in claims.
// Claims are validated (including deep field validation) before signing.
// The caller's claims struct is not modified; timing fields and defaults
// are set internally during signing and restored afterward.
//
// Returns errors:
//   - [ErrProcessorClosed]: processor has been closed
//   - [ErrInvalidClaims]: claims failed validation (missing required fields, injection patterns, etc.)
//   - [ErrRateLimitExceeded]: rate limit exceeded for the claims' subject/user
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
	if err := p.beginOp(); err != nil {
		return "", err
	}
	defer p.endOp()

	if err := validateCustomClaims(claims); err != nil {
		return "", err
	}

	return createTokenWithCustomClaims(p, claims, p.accessTokenTTL, TokenTypeAccess)
}

// Validate validates a JWT access token and returns the parsed Claims.
// Returns a value copy of the claims, whether the token is valid, and any error.
// The token is checked for signature validity, expiration, issuer, audience,
// and blacklist status before claims validation.
//
// Returns errors:
//   - [ErrProcessorClosed]: processor has been closed
//   - [ErrEmptyToken]: empty token string
//   - [ErrInvalidToken]: malformed token or invalid signature
//   - [ErrAlgorithmMismatch]: token algorithm does not match configured method
//   - [ErrTokenExpired]: token has expired
//   - [ErrTokenNotValidYet]: token's nbf claim is in the future
//   - [ErrTokenInvalidIssuer]: token issuer does not match configured issuer
//   - [ErrTokenInvalidAudience]: token audience does not match configured audience
//   - [ErrTokenRevoked]: token has been revoked
//   - [ErrInvalidClaims]: claims failed validation
//
// Example:
//
//	claims, valid, err := processor.Validate(tokenString)
//	if valid {
//	    fmt.Println(claims.UserID)
//	}
func (p *Processor) Validate(tokenString string) (Claims, bool, error) {
	if err := p.beginOp(); err != nil {
		return Claims{}, false, err
	}
	defer p.endOp()
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
	if err := p.beginOp(); err != nil {
		return "", err
	}
	defer p.endOp()

	if err := validateCustomClaims(claims); err != nil {
		return "", err
	}

	return createTokenWithCustomClaims(p, claims, p.refreshTokenTTL, TokenTypeRefresh)
}

// Refresh refreshes an existing refresh token and returns a new access token.
// The refresh token is validated (signature, expiration, blacklist) before
// a new access token is created. The original refresh token's claims are copied;
// IssuedAt, ExpiresAt, and ID are reset and regenerated for the new token.
//
// Tokens with token_type "access" are rejected to prevent access tokens from
// being used to obtain new tokens. Tokens without a token_type (created before
// this field was added) are accepted for backward compatibility.
//
// Returns errors:
//   - [ErrProcessorClosed]: processor has been closed
//   - [ErrEmptyToken]: empty token string
//   - [ErrInvalidToken]: malformed token or invalid signature
//   - [ErrAlgorithmMismatch]: token algorithm does not match configured method
//   - [ErrTokenExpired]: refresh token has expired
//   - [ErrTokenNotValidYet]: token's nbf claim is in the future
//   - [ErrTokenInvalidIssuer]: token issuer does not match configured issuer
//   - [ErrTokenInvalidAudience]: token audience does not match configured audience
//   - [ErrTokenRevoked]: refresh token has been revoked
//   - [ErrInvalidClaims]: claims failed validation
//   - [ErrTokenTypeMismatch]: token is an access token, not a refresh token
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
	if err := p.beginOp(); err != nil {
		return "", err
	}
	defer p.endOp()
	if err := requireToken(refreshTokenString); err != nil {
		return "", err
	}

	claims, err := p.validateTokenFully(refreshTokenString)
	if err != nil {
		return "", err
	}

	if claims.TokenType == TokenTypeAccess {
		return "", fmt.Errorf("%w: expected refresh token, got access token", ErrTokenTypeMismatch)
	}

	claims.IssuedAt = NumericDate{}
	claims.ExpiresAt = NumericDate{}
	claims.ID = ""

	return createTokenWithCustomClaims(p, &claims, p.accessTokenTTL, TokenTypeAccess)
}

// RefreshInto refreshes a custom-claims refresh token into a new access token.
// The claims parameter must be a pointer to a type implementing CustomClaims.
// The original claims object is not modified; timing fields (IssuedAt, ExpiresAt, ID)
// are temporarily reset during token creation and restored afterward,
// even if an error or panic occurs.
//
// Tokens with token_type "access" are rejected to prevent access tokens from
// being used to obtain new tokens. Tokens without a token_type are accepted
// for backward compatibility.
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
	if err := p.beginOp(); err != nil {
		return "", err
	}
	defer p.endOp()
	if err := requireToken(refreshTokenString); err != nil {
		return "", err
	}

	if err := p.validateCustomTokenFully(refreshTokenString, claims); err != nil {
		return "", err
	}

	rc := claims.GetRegisteredClaims()
	if rc.TokenType == TokenTypeAccess {
		return "", fmt.Errorf("%w: expected refresh token, got access token", ErrTokenTypeMismatch)
	}

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

	return createTokenWithCustomClaims(p, claims, p.accessTokenTTL, TokenTypeAccess)
}

// Close releases resources and securely clears sensitive data.
// It is safe to call Close multiple times; subsequent calls return ErrProcessorClosed.
// Always call Close when the processor is no longer needed to zero the secret key.
func (p *Processor) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return ErrProcessorClosed
	}

	// Acquire write lock to wait for all in-flight operations to complete.
	p.mu.Lock()

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
		p.secretKey = nil
	}
	p.asymmetricKey = nil
	p.verificationKey = nil

	// Clear HMAC hasher pools to prevent stale key material from persisting
	// after key rotation. Global pool is safe to drain — all Processor instances
	// are closed before creating new ones with a different key.
	if !p.isAsymmetric {
		internal.ClearHMACCaches()
	}

	p.mu.Unlock()

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
	if err := p.beginOp(); err != nil {
		return err
	}
	defer p.endOp()
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
	if err := p.beginOp(); err != nil {
		return nil, false, err
	}
	defer p.endOp()
	if err := requireToken(tokenString); err != nil {
		return nil, false, err
	}

	if err := p.validateCustomTokenFully(tokenString, claims); err != nil {
		return nil, false, err
	}

	return claims, true, nil
}

// getVerificationKey returns the appropriate key for token verification.
func (p *Processor) getVerificationKey() any {
	if p.isAsymmetric {
		return p.verificationKey
	}
	return p.secretKey
}

// beginOp acquires a read lock and checks that the processor is active.
// The read lock is held for the duration of the operation, preventing Close()
// from clearing fields while the operation is in flight.
func (p *Processor) beginOp() error {
	p.mu.RLock()
	if p.closed.Load() {
		p.mu.RUnlock()
		return ErrProcessorClosed
	}
	return nil
}

// endOp releases the read lock acquired by beginOp.
func (p *Processor) endOp() {
	p.mu.RUnlock()
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
	if p.signingMethodImpl == nil {
		return "", fmt.Errorf("signing method not initialized")
	}

	// Use typed path for HMAC to avoid interface boxing of p.secretKey.
	if !p.isAsymmetric {
		if p.secretKey == nil {
			return "", fmt.Errorf("signing key not configured")
		}
		return internal.SignTokenHMAC(string(p.signingMethod), claims, p.signingMethodImpl, p.secretKey)
	}

	key := p.asymmetricKey
	if key == nil {
		return "", fmt.Errorf("signing key not configured")
	}

	return internal.SignToken(string(p.signingMethod), claims, p.signingMethodImpl, key)
}

func (p *Processor) parseToken(tokenString string, claims any) (*internal.Core, error) {
	if !p.isAsymmetric {
		return internal.ParseWithClaimsHMAC(tokenString, claims, p.secretKey, string(p.signingMethod))
	}
	return internal.ParseWithClaims(tokenString, claims, p.keyFunc, string(p.signingMethod))
}

// keyFunc validates the algorithm header and returns the verification key.
func (p *Processor) keyFunc(token *internal.Core) (any, error) {
	// Read cached Alg from fast-path parsing first (avoids Header map lookup
	// and string→any type assertion). Falls back to Header for slow-path tokens.
	alg := token.Alg
	if alg == "" {
		var ok bool
		alg, ok = token.Header["alg"].(string)
		if !ok || alg != string(p.signingMethod) {
			return nil, ErrAlgorithmMismatch
		}
	} else if alg != string(p.signingMethod) {
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

func (p *Processor) validateTokenInternal(tokenString string) (Claims, error) {
	claims := getClaims()
	defer putClaims(claims)

	token, err := p.parseToken(tokenString, claims)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	defer internal.ReleaseCore(token)

	if !token.Valid {
		return Claims{}, ErrInvalidToken
	}

	if err := p.validateRegistered(&claims.RegisteredClaims); err != nil {
		return Claims{}, err
	}

	// json.Unmarshal creates fresh backing arrays for slices and maps,
	// and pool Claims is reset (fields nil'd) before reuse,
	// so returned value never shares mutable data with a subsequent pool user.
	return *claims, nil
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

// Revoke adds a token to the blacklist by verifying its signature and
// extracting the token ID (jti). Only tokens with a valid signature can be
// revoked, preventing malicious actors from blacklisting arbitrary token IDs.
//
// The token's expiration is used to determine the blacklist entry TTL, bounded
// by [DefaultBlacklistTTL] and [MaxBlacklistTTL]. Expired tokens can still be
// revoked since the blacklist entry will be cleaned up automatically.
//
// Returns errors:
//   - [ErrProcessorClosed]: processor has been closed
//   - [ErrEmptyToken]: empty token string
//   - [ErrBlacklistNotConfigured]: blacklist is not configured
//   - [ErrInvalidToken]: invalid signature or malformed token
//   - [ErrTokenMissingID]: token does not contain a jti claim
func (p *Processor) Revoke(tokenString string) error {
	if err := p.beginOp(); err != nil {
		return err
	}
	defer p.endOp()
	if err := requireToken(tokenString); err != nil {
		return err
	}

	if p.blacklistManager == nil {
		return ErrBlacklistNotConfigured
	}

	// Verify signature before extracting jti to prevent forgery.
	claims := getClaims()
	defer putClaims(claims)

	token, err := p.parseToken(tokenString, claims)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	defer internal.ReleaseCore(token)

	if !token.Valid {
		return ErrInvalidToken
	}

	// Verify the token belongs to this processor's issuer/audience.
	if p.issuer != "" && claims.Issuer != p.issuer {
		return ErrTokenInvalidIssuer
	}
	if p.audience != "" && !slices.Contains(claims.Audience, p.audience) {
		return ErrTokenInvalidAudience
	}

	if claims.ID == "" {
		return ErrTokenMissingID
	}

	return p.blacklistManager.BlacklistVerified(claims.ID, claims.ExpiresAt.Time)
}

// IsRevoked checks if a token has been revoked by verifying its signature and
// looking up its ID in the blacklist. Returns false if the blacklist is not configured.
func (p *Processor) IsRevoked(tokenString string) (bool, error) {
	if err := p.beginOp(); err != nil {
		return false, err
	}
	defer p.endOp()
	if err := requireToken(tokenString); err != nil {
		return false, err
	}

	if p.blacklistManager == nil {
		return false, nil
	}

	// Verify signature before extracting jti to prevent forgery.
	claims := getClaims()
	defer putClaims(claims)

	token, err := p.parseToken(tokenString, claims)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	defer internal.ReleaseCore(token)

	if !token.Valid {
		return false, ErrInvalidToken
	}

	if p.issuer != "" && claims.Issuer != p.issuer {
		return false, ErrTokenInvalidIssuer
	}
	if p.audience != "" && !slices.Contains(claims.Audience, p.audience) {
		return false, ErrTokenInvalidAudience
	}

	if claims.ID == "" {
		return false, ErrTokenMissingID
	}

	return p.blacklistManager.IsBlacklisted(claims.ID)
}
