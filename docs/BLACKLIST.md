# JWT Library - Blacklist & Token Revocation Guide

This guide covers the revocation subsystem: the built-in in-memory blacklist,
its saturation semantics, and a production-ready Redis reference
implementation of the `BlacklistStore` interface.

## Overview

Revocation is keyed by the token's `jti` (JWT ID). `Revoke(tokenString)`
verifies the signature first — so forged tokens cannot pollute the blacklist —
extracts the `jti`, and stores an entry that expires with the token:

- No `exp` on the token → entry defaults to 7 days
- Entry TTL is capped at 30 days so a crafted `exp` cannot pin long-lived
  entries (DoS guard)
- Expired tokens can still be revoked; entries are cleaned up automatically

## Built-in Memory Store

`DefaultBlacklistConfig()` provisions a bounded in-memory store:

```go
cfg := jwt.DefaultConfig()
cfg.Blacklist.MaxSize = 100_000                 // default
cfg.Blacklist.CleanupInterval = 5 * time.Minute // default
```

### Saturation semantics (important)

When the store reaches `MaxSize`, expired entries are removed first; if it is
still full, entries with the **earliest expiry are evicted — which may drop
still-active revocations (fail-open under saturation)**.

Mitigations:

1. **Size for peak revocation volume** — roughly: logout rate × refresh-token TTL
2. Entries expire with their tokens, so steady-state size ≈ revocations issued within the longest token TTL
3. For strict guarantees, supply a custom store (below) — the built-in store
   trades strictness for zero operational dependencies

## Custom Store: Redis Reference Implementation

The `BlacklistStore` interface has three methods. Redis maps naturally: one
key per revoked `jti` with a TTL equal to the token's remaining lifetime, so
cleanup is automatic and **active revocations are never evicted** (subject to
your Redis `maxmemory-policy` — avoid `allkeys-*` eviction policies).

> The snippet uses `github.com/redis/go-redis/v9`. Add it to **your**
> application's `go.mod` — the JWT library itself has zero dependencies.

```go
package auth

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisBlacklistStore is a jwt.BlacklistStore backed by Redis. Keys expire
// with the revoked tokens, so no background cleanup is needed.
// All methods are safe for concurrent use.
type RedisBlacklistStore struct {
	client *redis.Client
}

func NewRedisBlacklistStore(addr, password string, db int) *RedisBlacklistStore {
	return &RedisBlacklistStore{
		client: redis.NewClient(&redis.Options{Addr: addr, Password: password, DB: db}),
	}
}

// Add stores the revocation with a TTL matching the token's remaining life.
// A non-positive remaining TTL (already-expired token) still records the
// entry briefly to defeat clock-skew replays.
//
// The BlacklistStore interface does not carry a context, so each call uses
// context.Background(); wrap the store in your own context-carrying type if
// you need per-request cancellation.
func (s *RedisBlacklistStore) Add(tokenID string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		ttl = time.Minute
	}
	return s.client.Set(context.Background(), "blacklist:"+tokenID, 1, ttl).Err()
}

// Contains reports whether the jti is currently revoked. Store errors are
// returned to the caller (fail-closed): the Processor surfaces them instead
// of silently treating the token as unrevoked.
func (s *RedisBlacklistStore) Contains(tokenID string) (bool, error) {
	n, err := s.client.Exists(context.Background(), "blacklist:"+tokenID).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// Close releases the Redis client.
func (s *RedisBlacklistStore) Close() error {
	return s.client.Close()
}
```

Wire it into the processor:

```go
store := auth.NewRedisBlacklistStore("localhost:6379", "", 0)
cfg := jwt.DefaultConfig()
cfg.Blacklist = jwt.BlacklistConfig{Store: store} // MaxSize/interval ignored
```

**Ownership note:** `Processor.Close()` closes the store. Do not share one
store instance across processors that may outlive each other.

### Strict single-use refresh under concurrency

`Config.RotateRefreshTokens` revokes the old refresh token before minting the
new one, but two *racing* `Refresh` calls can both pass validation before
either revocation lands (both then succeed). To remove the window inside the
store, make `Add` fail when the `jti` is already recorded — Redis `SET key 1
NX` — so the second racing refresh aborts with `ErrRefreshRotationFailed`
instead of minting a second token: the check-and-set happens atomically
inside Redis rather than across two library calls.

## See Also

- [Security Guide](SECURITY.md) — key management and attack protections
- [Best Practices](BEST_PRACTICES.md) — refresh/revocation patterns
- [API Reference](API.md) — `Revoke`, `IsRevoked`, `BlacklistStore`
