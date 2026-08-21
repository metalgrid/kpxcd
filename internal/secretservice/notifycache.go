//go:build linux

package secretservice

import (
	"sync"
	"time"
)

// notifyCacheMaxEntries bounds the suppression cache. When a new key would
// exceed this size, expired entries are swept first; if the cache is still
// full, the entry that expires soonest is evicted.
const notifyCacheMaxEntries = 256

// notifyCache is a tiny TTL registry of apps that were recently notified
// about secret access. It keeps repeated reads from one app from spamming
// desktop notifications: the first access notifies, further accesses within
// the TTL are suppressed, and every access refreshes the TTL so an app that
// stays active keeps its entry alive.
//
// The zero value is ready to use.
type notifyCache struct {
	mu      sync.Mutex
	entries map[string]time.Time // cache key -> expiry time
	now     func() time.Time     // overridable clock for tests
}

// allow reports whether a notification should be shown for key now. It
// writes a fresh TTL for the key either way, so every access refreshes
// suppression. A ttl of zero or less disables suppression and never caches.
//
// An entry is cached before the notification is sent. If the notification
// daemon is unavailable, the app stays suppressed for the TTL.
func (c *notifyCache) allow(key string, ttl time.Duration) bool {
	if ttl <= 0 {
		return true
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.clock()
	if expiry, ok := c.entries[key]; ok && now.Before(expiry) {
		c.entries[key] = now.Add(ttl)
		return false
	}

	if c.entries == nil {
		c.entries = make(map[string]time.Time)
	}
	if _, exists := c.entries[key]; !exists && len(c.entries) >= notifyCacheMaxEntries {
		c.pruneLocked(now)
		if len(c.entries) >= notifyCacheMaxEntries {
			c.evictSoonestLocked()
		}
	}
	c.entries[key] = now.Add(ttl)
	return true
}

// clock returns the current time, honoring the test override.
func (c *notifyCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// pruneLocked removes expired entries. Callers must hold c.mu.
func (c *notifyCache) pruneLocked(now time.Time) {
	for key, expiry := range c.entries {
		if !now.Before(expiry) {
			delete(c.entries, key)
		}
	}
}

// evictSoonestLocked removes the entry with the earliest expiry time.
// Callers must hold c.mu.
func (c *notifyCache) evictSoonestLocked() {
	var soonestKey string
	var soonest time.Time
	for key, expiry := range c.entries {
		if soonestKey == "" || expiry.Before(soonest) {
			soonestKey, soonest = key, expiry
		}
	}
	if soonestKey != "" {
		delete(c.entries, soonestKey)
	}
}

// size returns the number of cached entries.
func (c *notifyCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
