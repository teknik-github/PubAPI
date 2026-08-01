// Package cache provides a small, thread-safe in-memory TTL cache used to
// avoid re-hitting slow or rate-limited third-party services.
package cache

import (
	"sync"
	"time"
)

type entry struct {
	value   any
	expires time.Time
}

// Cache is a concurrency-safe key/value store with per-entry expiry.
type Cache struct {
	mu    sync.RWMutex
	items map[string]entry
	stop  chan struct{}

	hits   uint64
	misses uint64
}

// New builds a cache and starts a background janitor that evicts expired
// entries every cleanupInterval.
func New(cleanupInterval time.Duration) *Cache {
	c := &Cache{
		items: make(map[string]entry),
		stop:  make(chan struct{}),
	}
	if cleanupInterval <= 0 {
		cleanupInterval = time.Minute
	}
	go c.janitor(cleanupInterval)
	return c
}

// Get returns the value for key if present and unexpired.
func (c *Cache) Get(key string) (any, bool) {
	c.mu.RLock()
	e, ok := c.items[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		return nil, false
	}
	c.mu.Lock()
	c.hits++
	c.mu.Unlock()
	return e.value, true
}

// Set stores value under key for the given ttl.
func (c *Cache) Set(key string, value any, ttl time.Duration) {
	c.mu.Lock()
	c.items[key] = entry{value: value, expires: time.Now().Add(ttl)}
	c.mu.Unlock()
}

// Stats returns cumulative hit/miss counts and the current entry count.
func (c *Cache) Stats() (hits, misses uint64, size int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses, len(c.items)
}

func (c *Cache) janitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			now := time.Now()
			c.mu.Lock()
			for k, e := range c.items {
				if now.After(e.expires) {
					delete(c.items, k)
				}
			}
			c.mu.Unlock()
		}
	}
}
