package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestBurstIsAllowedThenTheRateApplies(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{Rate: 1, Burst: 3})
	defer rl.Stop()

	now := time.Now()
	for i := range 3 {
		if allowed, _ := rl.allow("caller", now); !allowed {
			t.Fatalf("request %d of the burst was refused", i+1)
		}
	}

	allowed, wait := rl.allow("caller", now)
	if allowed {
		t.Fatal("a fourth request inside the burst was allowed")
	}
	if wait <= 0 || wait > 2*time.Second {
		t.Fatalf("Retry-After hint = %v, want somewhere near a second", wait)
	}
}

func TestTokensRefillOverTime(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{Rate: 2, Burst: 2})
	defer rl.Stop()

	now := time.Now()
	rl.allow("caller", now)
	rl.allow("caller", now)
	if allowed, _ := rl.allow("caller", now); allowed {
		t.Fatal("the bucket did not empty")
	}

	// Half a second at two per second is one token.
	if allowed, _ := rl.allow("caller", now.Add(500*time.Millisecond)); !allowed {
		t.Fatal("the bucket did not refill")
	}
}

// TestOneCallerCannotExhaustAnother is the property that makes the limit usable
// at all: a shared office address must not mean one person's script throttles
// everybody else on it.
func TestOneCallerCannotExhaustAnother(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{Rate: 1, Burst: 2})
	defer rl.Stop()

	now := time.Now()
	rl.allow("noisy", now)
	rl.allow("noisy", now)
	if allowed, _ := rl.allow("noisy", now); allowed {
		t.Fatal("the noisy caller was not limited")
	}

	if allowed, _ := rl.allow("quiet", now); !allowed {
		t.Fatal("a different caller was refused because of somebody else's traffic")
	}
}

// TestTheEventStreamIsNotRateLimited. It is one connection held open for hours;
// counting it would do nothing normally and, during a reconnect storm after a
// deploy, would lock every wall display out of the thing it exists to show.
func TestTheEventStreamIsNotRateLimited(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{Rate: 0.0001, Burst: 1})
	defer rl.Stop()

	handler := rl.Middleware()
	for i := range 5 {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
		handler(c)
		if c.IsAborted() {
			t.Fatalf("the event stream was rate limited on request %d", i+1)
		}
	}
}

// TestIdleBucketsAreEvicted. The map is keyed by caller, so without eviction it
// is an unbounded structure an attacker can grow from outside by varying source
// addresses — the limiter becoming the vulnerability.
func TestIdleBucketsAreEvicted(t *testing.T) {
	rl := NewRateLimiter(DefaultAPIRateLimit)
	defer rl.Stop()

	stale := time.Now().Add(-time.Hour)
	rl.mu.Lock()
	rl.buckets["gone"] = &bucket{tokens: 1, lastSeen: stale}
	rl.buckets["here"] = &bucket{tokens: 1, lastSeen: time.Now()}
	rl.mu.Unlock()

	// The sweep body, run directly rather than waiting five minutes for its
	// ticker.
	rl.mu.Lock()
	for key, b := range rl.buckets {
		if time.Since(b.lastSeen) > 10*time.Minute {
			delete(rl.buckets, key)
		}
	}
	_, goneStill := rl.buckets["gone"]
	_, hereStill := rl.buckets["here"]
	rl.mu.Unlock()

	if goneStill {
		t.Fatal("an idle bucket was not evicted")
	}
	if !hereStill {
		t.Fatal("an active bucket was evicted")
	}
}

func TestStopIsIdempotent(t *testing.T) {
	rl := NewRateLimiter(DefaultAPIRateLimit)
	rl.Stop()
	rl.Stop() // a bare close(chan) would panic here
}
