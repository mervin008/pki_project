package middleware

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimitConfig describes one bucket policy.
type RateLimitConfig struct {
	// Rate is the sustained requests per second allowed.
	Rate float64
	// Burst is how many may arrive at once before the rate applies.
	//
	// A dashboard opens a dozen panels and an event stream on load, so a burst
	// well above the sustained rate is not generosity — a limit that refuses
	// the first page a person sees is a limit that gets turned off.
	Burst float64
}

// Defaults chosen from what the console actually does rather than from a round
// number. Loading the dashboard is roughly fifteen requests; a person clicking
// through views settles well under one per second.
var (
	DefaultAPIRateLimit   = RateLimitConfig{Rate: 10, Burst: 40}
	DefaultLoginRateLimit = RateLimitConfig{Rate: 0.2, Burst: 5}
)

// bucket is a token bucket, refilled lazily.
//
// Lazily rather than by a ticker: a ticker per client is a goroutine per
// client, and the arithmetic on read is cheaper than the scheduling.
type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// RateLimiter enforces a request rate per caller.
//
// In-process, and therefore per-replica. That is a real limitation and worth
// stating plainly: behind a load balancer with N replicas the effective limit
// is N times what is configured here. It is a guard against a runaway script
// and a crude brute-force brake, not a defence against a distributed attack —
// for that the limit belongs in front of the application, where the traffic
// arrives.
//
// Sign-in is deliberately not defended by this. The per-account lockout in the
// store is, because it survives an attacker spreading attempts across replicas
// and this cannot.
type RateLimiter struct {
	cfg RateLimitConfig

	mu      sync.Mutex
	buckets map[string]*bucket

	stopCh chan struct{}
	once   sync.Once
}

// NewRateLimiter starts a limiter and its eviction sweep.
func NewRateLimiter(cfg RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		cfg:     cfg,
		buckets: make(map[string]*bucket),
		stopCh:  make(chan struct{}),
	}
	go rl.sweep()
	return rl
}

// sweep discards buckets nobody is using.
//
// Without it the map is an unbounded structure keyed by client address, which
// is a memory leak an attacker can drive from outside by varying source
// addresses — the limiter becoming the vulnerability.
func (rl *RateLimiter) sweep() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCh:
			return
		case now := <-ticker.C:
			rl.mu.Lock()
			for key, b := range rl.buckets {
				// A full bucket is indistinguishable from no bucket, so
				// dropping it loses nothing.
				if now.Sub(b.lastSeen) > 10*time.Minute {
					delete(rl.buckets, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// Stop ends the sweep. Idempotent: a bare close would panic on a second call,
// which is the bug this codebase already fixed once in Scheduler.
func (rl *RateLimiter) Stop() {
	rl.once.Do(func() { close(rl.stopCh) })
}

// allow reports whether one request may proceed, and how long until the next
// one could.
func (rl *RateLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[key]
	if !ok {
		rl.buckets[key] = &bucket{tokens: rl.cfg.Burst - 1, lastSeen: now}
		return true, 0
	}

	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens = math.Min(rl.cfg.Burst, b.tokens+elapsed*rl.cfg.Rate)
	b.lastSeen = now

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}

	// How long until one whole token exists.
	wait := time.Duration((1 - b.tokens) / rl.cfg.Rate * float64(time.Second))
	return false, wait
}

// Middleware returns the Gin handler.
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// The event stream is one connection held open for hours. Counting it
		// against a rate would either do nothing or, on reconnect storms after
		// a deploy, lock every wall display out of the thing they exist to
		// show.
		if c.Request.URL.Path == "/api/v1/events" {
			c.Next()
			return
		}

		allowed, wait := rl.allow(rateLimitKey(c), time.Now())
		if !allowed {
			seconds := int(math.Ceil(wait.Seconds()))
			if seconds < 1 {
				seconds = 1
			}
			c.Header("Retry-After", strconv.Itoa(seconds))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": fmt.Sprintf(
					"too many requests; try again in about %d second(s). This limit is per "+
						"replica and is meant to catch a runaway client, not to shape traffic",
					seconds),
			})
			return
		}
		c.Next()
	}
}

// rateLimitKey identifies the caller.
//
// Keyed on the authenticated identity where there is one, so that a busy
// operator behind a shared NAT is not throttled by a colleague on the same
// address, and so that a single credential cannot escape its limit by arriving
// from many addresses. Unauthenticated callers fall back to the client address,
// which is all there is to key on.
func rateLimitKey(c *gin.Context) string {
	if id := c.GetString(ContextUserDBID); id != "" {
		return "user:" + id
	}
	if id := c.GetString(ContextUserID); id != "" {
		return "subject:" + id
	}
	return "ip:" + c.ClientIP()
}
