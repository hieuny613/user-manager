package utils

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiterStore manages rate limiters for different clients
type RateLimiterStore struct {
	limiters map[string]*rateLimiterEntry
	mutex    sync.RWMutex
}

type rateLimiterEntry struct {
	limiter   *rate.Limiter
	createdAt time.Time
	window    time.Duration
}

// NewRateLimiterStore creates a new rate limiter store
func NewRateLimiterStore() *RateLimiterStore {
	store := &RateLimiterStore{
		limiters: make(map[string]*rateLimiterEntry),
	}

	// Start a cleanup goroutine
	go store.cleanup()

	return store
}

// Allow checks if a request is allowed based on rate limits
func (s *RateLimiterStore) Allow(key string, limit int, burst int, window time.Duration) (bool, int, int64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Get or create limiter for this key
	entry, exists := s.limiters[key]
	if !exists || entry.window != window {
		// Create a new limiter with the specified rate
		limiter := rate.NewLimiter(rate.Limit(float64(limit)/window.Seconds()), burst)
		entry = &rateLimiterEntry{
			limiter:   limiter,
			createdAt: time.Now(),
			window:    window,
		}
		s.limiters[key] = entry
	}

	// Check if request is allowed
	allowed := entry.limiter.Allow()

	// Calculate tokens remaining
	remaining := int(entry.limiter.Burst() - entry.limiter.Tokens())
	if remaining < 0 {
		remaining = 0
	}

	// Calculate reset time in seconds
	resetSeconds := int64(entry.limiter.Tokens() / float64(entry.limiter.Limit()))
	if resetSeconds < 1 {
		resetSeconds = 1
	}

	return allowed, remaining, resetSeconds
}

// cleanup periodically removes old limiters
func (s *RateLimiterStore) cleanup() {
	for {
		time.Sleep(10 * time.Minute)

		s.mutex.Lock()
		now := time.Now()

		// Remove limiters older than 1 hour
		for key, entry := range s.limiters {
			if now.Sub(entry.createdAt) > time.Hour {
				delete(s.limiters, key)
			}
		}

		s.mutex.Unlock()
	}
}
