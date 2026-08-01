package service

import (
	"time"

	"pubapi/internal/cache"
)

// extCache backs all cached external lookups. TTLs are chosen per data type:
// volatile records get short TTLs, stable registry data gets long ones.
var (
	extCache     = cache.New(time.Minute)
	cacheEnabled = true
)

// Per-type cache lifetimes.
const (
	ttlDNS     = 60 * time.Second
	ttlPassive = 10 * time.Minute
	ttlWhois   = 6 * time.Hour
	ttlWayback = 1 * time.Hour
	ttlGeoIP   = 24 * time.Hour
)

// SetCacheEnabled toggles the external-lookup cache at runtime.
func SetCacheEnabled(on bool) { cacheEnabled = on }

// CacheStats exposes cumulative cache metrics.
func CacheStats() (hits, misses uint64, size int) { return extCache.Stats() }

// cacheGet returns a typed cached value when caching is on and the key is live.
func cacheGet[T any](key string) (T, bool) {
	var zero T
	if !cacheEnabled {
		return zero, false
	}
	v, ok := extCache.Get(key)
	if !ok {
		return zero, false
	}
	t, ok := v.(T)
	return t, ok
}

// cacheSet stores a value when caching is enabled.
func cacheSet[T any](key string, val T, ttl time.Duration) {
	if !cacheEnabled {
		return
	}
	extCache.Set(key, val, ttl)
}
