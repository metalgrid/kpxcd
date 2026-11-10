//go:build linux

package secretservice

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// fakeClock returns a clock whose time the test controls.
type fakeClock struct{ t time.Time }

func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

func newNotifyCacheWithClock() (*fakeClock, *notifyCache) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	return clock, &notifyCache{now: func() time.Time { return clock.t }}
}

var _ = Describe("notifyCache", func() {
	It("notifies on first access", func() {
		_, cache := newNotifyCacheWithClock()
		Expect(cache.allow("exe:/usr/bin/git", 5*time.Minute)).To(BeTrue())
	})

	It("suppresses accesses within the TTL", func() {
		clock, cache := newNotifyCacheWithClock()
		cache.allow("exe:/usr/bin/git", 5*time.Minute)
		clock.advance(4 * time.Minute)
		Expect(cache.allow("exe:/usr/bin/git", 5*time.Minute)).To(BeFalse(),
			"access within the TTL should be suppressed")
	})

	It("notifies again after the TTL expires", func() {
		clock, cache := newNotifyCacheWithClock()
		cache.allow("exe:/usr/bin/git", 5*time.Minute)
		clock.advance(5*time.Minute + time.Second)
		Expect(cache.allow("exe:/usr/bin/git", 5*time.Minute)).To(BeTrue())
	})

	It("refreshes the TTL on a suppressed re-access", func() {
		clock, cache := newNotifyCacheWithClock()
		const ttl = 5 * time.Minute

		Expect(cache.allow("exe:/usr/bin/git", ttl)).To(BeTrue())
		// Suppressed access near the end of the window must extend the TTL.
		clock.advance(ttl - 10*time.Second)
		Expect(cache.allow("exe:/usr/bin/git", ttl)).To(BeFalse())
		// Past the original window, still inside the refreshed one.
		clock.advance(time.Minute)
		Expect(cache.allow("exe:/usr/bin/git", ttl)).To(BeFalse())
		// After the refreshed window expires, notify again.
		clock.advance(ttl)
		Expect(cache.allow("exe:/usr/bin/git", ttl)).To(BeTrue())
	})

	It("treats a zero and negative TTL as always-notify and caches nothing", func() {
		_, cache := newNotifyCacheWithClock()
		for i := 0; i < 3; i++ {
			Expect(cache.allow("exe:/usr/bin/git", 0)).To(BeTrue(), "ttl of zero should always notify")
		}
		Expect(cache.size()).To(Equal(0), "ttl of zero should not cache entries")
		Expect(cache.allow("exe:/usr/bin/git", -time.Minute)).To(BeTrue())
	})

	It("keeps keys independent", func() {
		clock, cache := newNotifyCacheWithClock()
		cache.allow("exe:/usr/bin/git", 5*time.Minute)
		Expect(cache.allow("exe:/usr/bin/firefox", 5*time.Minute)).To(BeTrue(),
			"a different app must not be suppressed by another app's entry")
		clock.advance(0)
		Expect(cache.allow("exe:/usr/bin/git", 5*time.Minute)).To(BeFalse(), "first app should still be suppressed")
	})

	It("stays bounded at capacity", func() {
		_, cache := newNotifyCacheWithClock()
		for i := 0; i < notifyCacheMaxEntries; i++ {
			cache.allow(fmt.Sprintf("exe:/usr/bin/app%d", i), time.Hour)
		}
		Expect(cache.size()).To(Equal(notifyCacheMaxEntries))

		cache.allow("exe:/usr/bin/one-too-many", time.Hour)
		Expect(cache.size()).To(Equal(notifyCacheMaxEntries), "insert at capacity must not grow the cache")
		Expect(cache.allow("exe:/usr/bin/one-too-many", time.Hour)).To(BeFalse(),
			"new app should be suppressed after being cached")
	})

	It("prunes expired entries before inserting at capacity", func() {
		clock, cache := newNotifyCacheWithClock()
		for i := 0; i < notifyCacheMaxEntries; i++ {
			cache.allow(fmt.Sprintf("exe:/usr/bin/app%d", i), time.Second)
		}
		clock.advance(time.Minute)

		cache.allow("exe:/usr/bin/next", time.Hour)
		Expect(cache.size()).To(Equal(1), "expired entries must be pruned before insert")
	})
})

var _ = Describe("CallerInfo.notifyCacheKey", func() {
	DescribeTable("picks the most specific identifier available",
		func(info CallerInfo, want string) {
			Expect(info.notifyCacheKey()).To(Equal(want))
		},
		Entry("exe wins", CallerInfo{Exe: "/usr/bin/git", Command: "/usr/bin/git clone", Sender: ":1.42"}, "exe:/usr/bin/git"),
		Entry("command fallback", CallerInfo{Command: "/usr/bin/firefox --profile", Sender: ":1.42"}, "cmd:/usr/bin/firefox"),
		Entry("sender fallback", CallerInfo{Sender: ":1.42"}, "sender::1.42"),
		Entry("unknown", CallerInfo{}, "unknown"),
	)
})
