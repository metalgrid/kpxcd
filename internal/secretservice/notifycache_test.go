//go:build linux

package secretservice

import (
	"fmt"
	"testing"
	"time"
)

// fakeClock returns a clock whose time the test controls.
type fakeClock struct{ t time.Time }

func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

func TestNotifyCacheFirstAccessNotifies(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	cache := &notifyCache{now: func() time.Time { return clock.t }}

	if !cache.allow("exe:/usr/bin/git", 5*time.Minute) {
		t.Error("first access should notify")
	}
}

func TestNotifyCacheSuppressesWithinTTL(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	cache := &notifyCache{now: func() time.Time { return clock.t }}

	cache.allow("exe:/usr/bin/git", 5*time.Minute)
	clock.advance(4 * time.Minute)
	if cache.allow("exe:/usr/bin/git", 5*time.Minute) {
		t.Error("access within the TTL should be suppressed")
	}
}

func TestNotifyCacheExpires(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	cache := &notifyCache{now: func() time.Time { return clock.t }}

	cache.allow("exe:/usr/bin/git", 5*time.Minute)
	clock.advance(5*time.Minute + time.Second)
	if !cache.allow("exe:/usr/bin/git", 5*time.Minute) {
		t.Error("access after the TTL should notify again")
	}
}

func TestNotifyCacheRefreshesTTLOnReAccess(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	cache := &notifyCache{now: func() time.Time { return clock.t }}
	const ttl = 5 * time.Minute

	if !cache.allow("exe:/usr/bin/git", ttl) {
		t.Fatal("first access should notify")
	}
	// Suppressed access near the end of the window must extend the TTL.
	clock.advance(ttl - 10*time.Second)
	if cache.allow("exe:/usr/bin/git", ttl) {
		t.Fatal("access within the TTL should be suppressed")
	}
	// Past the original window, still inside the refreshed one.
	clock.advance(time.Minute)
	if cache.allow("exe:/usr/bin/git", ttl) {
		t.Error("access within the refreshed TTL should be suppressed")
	}
	// After the refreshed window expires, notify again.
	clock.advance(ttl)
	if !cache.allow("exe:/usr/bin/git", ttl) {
		t.Error("access after the refreshed TTL should notify")
	}
}

func TestNotifyCacheZeroTTLDisablesSuppression(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	cache := &notifyCache{now: func() time.Time { return clock.t }}

	for i := 0; i < 3; i++ {
		if !cache.allow("exe:/usr/bin/git", 0) {
			t.Error("ttl of zero should always notify")
		}
	}
	if got := cache.size(); got != 0 {
		t.Errorf("ttl of zero should not cache entries, size = %d", got)
	}
	if !cache.allow("exe:/usr/bin/git", -time.Minute) {
		t.Error("negative ttl should always notify")
	}
}

func TestNotifyCacheKeysAreIndependent(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	cache := &notifyCache{now: func() time.Time { return clock.t }}

	cache.allow("exe:/usr/bin/git", 5*time.Minute)
	if !cache.allow("exe:/usr/bin/firefox", 5*time.Minute) {
		t.Error("a different app must not be suppressed by another app's entry")
	}
	if cache.allow("exe:/usr/bin/git", 5*time.Minute) {
		t.Error("first app should still be suppressed")
	}
}

func TestNotifyCacheStaysBounded(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	cache := &notifyCache{now: func() time.Time { return clock.t }}

	// Fill the cache with distinct apps holding long TTLs.
	for i := 0; i < notifyCacheMaxEntries; i++ {
		cache.allow(fmt.Sprintf("exe:/usr/bin/app%d", i), time.Hour)
	}
	if got := cache.size(); got != notifyCacheMaxEntries {
		t.Fatalf("size = %d, want %d", got, notifyCacheMaxEntries)
	}

	// One more distinct app must not grow the cache.
	cache.allow("exe:/usr/bin/one-too-many", time.Hour)
	if got := cache.size(); got != notifyCacheMaxEntries {
		t.Errorf("size = %d, want %d after insert at capacity", got, notifyCacheMaxEntries)
	}
	// The new app must still be suppressed afterwards.
	if cache.allow("exe:/usr/bin/one-too-many", time.Hour) {
		t.Error("new app should be suppressed after being cached")
	}
}

func TestNotifyCachePrunesExpiredEntries(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	cache := &notifyCache{now: func() time.Time { return clock.t }}

	// Fill with short-lived entries, let them expire.
	for i := 0; i < notifyCacheMaxEntries; i++ {
		cache.allow(fmt.Sprintf("exe:/usr/bin/app%d", i), time.Second)
	}
	clock.advance(time.Minute)

	// A new app at capacity must prune the expired entries first.
	cache.allow("exe:/usr/bin/next", time.Hour)
	if got := cache.size(); got != 1 {
		t.Errorf("size = %d, want 1 after pruning expired entries", got)
	}
}

func TestCallerInfoNotifyCacheKeyPrecedence(t *testing.T) {
	tests := []struct {
		name string
		info CallerInfo
		want string
	}{
		{
			name: "exe wins",
			info: CallerInfo{Exe: "/usr/bin/git", Command: "/usr/bin/git clone", Sender: ":1.42"},
			want: "exe:/usr/bin/git",
		},
		{
			name: "command fallback",
			info: CallerInfo{Command: "/usr/bin/firefox --profile", Sender: ":1.42"},
			want: "cmd:/usr/bin/firefox",
		},
		{
			name: "sender fallback",
			info: CallerInfo{Sender: ":1.42"},
			want: "sender::1.42",
		},
		{
			name: "unknown",
			info: CallerInfo{},
			want: "unknown",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.info.notifyCacheKey(); got != tc.want {
				t.Errorf("notifyCacheKey() = %q, want %q", got, tc.want)
			}
		})
	}
}
