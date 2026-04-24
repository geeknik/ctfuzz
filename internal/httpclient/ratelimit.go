package httpclient

import (
	crand "crypto/rand"
	"context"
	"encoding/binary"
	"math"
	"sync"
	"time"
)

type tokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	capacity   float64
	fillRate   float64
	lastUpdate time.Time
}

func (b *tokenBucket) acquire(ctx context.Context) error {
	for {
		b.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(b.lastUpdate).Seconds()
		if elapsed > 0 {
			b.tokens = math.Min(b.capacity, b.tokens+elapsed*b.fillRate)
			b.lastUpdate = now
		}
		if b.tokens >= 1.0 {
			b.tokens -= 1.0
			b.mu.Unlock()
			return nil
		}
		needed := (1.0 - b.tokens) / b.fillRate
		wait := time.Duration(needed * float64(time.Second))
		if wait < 5*time.Millisecond {
			wait = 5 * time.Millisecond
		}
		b.mu.Unlock()

		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

type hostLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*tokenBucket
	rate     float64
	capacity float64
}

func newHostLimiter(rps float64) *hostLimiter {
	if rps <= 0 {
		return nil
	}
	capacity := math.Max(1.0, rps)
	return &hostLimiter{
		buckets:  map[string]*tokenBucket{},
		rate:     rps,
		capacity: capacity,
	}
}

func (h *hostLimiter) Acquire(ctx context.Context, host string) error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	b, ok := h.buckets[host]
	if !ok {
		b = &tokenBucket{
			tokens:     h.capacity,
			capacity:   h.capacity,
			fillRate:   h.rate,
			lastUpdate: time.Now(),
		}
		h.buckets[host] = b
	}
	h.mu.Unlock()
	return b.acquire(ctx)
}

// jitteredBackoff returns a capped exponential backoff delay with ±50% jitter.
// attempt is 1-based (first retry attempt).
func jitteredBackoff(base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		base = 100 * time.Millisecond
	}
	if attempt < 1 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 4 {
		shift = 4
	}
	scaled := base << shift
	if scaled <= 0 {
		scaled = base
	}
	// ±50% jitter: result in [scaled/2, 3*scaled/2).
	span := int64(scaled)
	if span <= 0 {
		return scaled
	}
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return scaled
	}
	n := int64(binary.BigEndian.Uint64(b[:]) >> 1)
	return scaled/2 + time.Duration(n%span)
}
