package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestJitteredBackoffBounds(t *testing.T) {
	base := 100 * time.Millisecond
	for attempt := 1; attempt <= 8; attempt++ {
		for i := 0; i < 32; i++ {
			got := jitteredBackoff(base, attempt)
			if got < 0 {
				t.Fatalf("attempt %d: negative backoff %v", attempt, got)
			}
			if got > 10*time.Second {
				t.Fatalf("attempt %d: backoff %v exceeds hard ceiling", attempt, got)
			}
		}
	}
}

func TestHostLimiterEnforcesRate(t *testing.T) {
	limiter := newHostLimiter(10) // 10 req/s, burst 10
	if limiter == nil {
		t.Fatal("expected limiter, got nil")
	}
	ctx := context.Background()
	host := "example.test"

	// Drain the initial burst.
	for i := 0; i < 10; i++ {
		if err := limiter.Acquire(ctx, host); err != nil {
			t.Fatalf("burst acquire %d: %v", i, err)
		}
	}

	start := time.Now()
	if err := limiter.Acquire(ctx, host); err != nil {
		t.Fatalf("post-burst acquire: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 50*time.Millisecond {
		t.Fatalf("expected the post-burst acquire to wait ~100ms, waited %v", elapsed)
	}
}

func TestHostLimiterNilDisabled(t *testing.T) {
	var h *hostLimiter
	if err := h.Acquire(context.Background(), "x"); err != nil {
		t.Fatalf("nil limiter must be a no-op, got %v", err)
	}
}

func TestHostLimiterCancelsOnContext(t *testing.T) {
	limiter := newHostLimiter(1) // very slow
	// Drain burst.
	_ = limiter.Acquire(context.Background(), "host")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := limiter.Acquire(ctx, "host"); err == nil {
		t.Fatal("expected context deadline error")
	}
}

func TestClientRetriesOnConnectionReset(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Fatalf("hijack not supported")
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				t.Fatalf("hijack failed: %v", err)
			}
			_ = conn.Close()
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	c, err := New(Config{
		Timeout:      2 * time.Second,
		MaxBodyRead:  4096,
		Retries:      3,
		RetryBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	res := c.Do(context.Background(), RequestSpec{
		URL:         server.URL + "/",
		Method:      "POST",
		ContentType: "application/json",
		Body:        []byte("{}"),
	})
	if res.Error != "" {
		t.Fatalf("expected retry to succeed, got error=%q attempts=%d", res.Error, attempts.Load())
	}
	if res.Status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.Status)
	}
	if attempts.Load() < 3 {
		t.Fatalf("expected at least 3 server hits, got %d", attempts.Load())
	}
}

func TestClientDoesNotRetryOn4xx(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	c, err := New(Config{
		Timeout:      2 * time.Second,
		MaxBodyRead:  4096,
		Retries:      3,
		RetryBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	res := c.Do(context.Background(), RequestSpec{
		URL:         server.URL + "/",
		Method:      "POST",
		ContentType: "application/json",
		Body:        []byte("{}"),
	})
	if res.Status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", res.Status)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("expected exactly one server hit on 4xx, got %d", got)
	}
}

func TestClientRejectsInvalidURLWithoutHittingNetwork(t *testing.T) {
	c, err := New(Config{Timeout: time.Second, MaxBodyRead: 1024})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	res := c.Do(context.Background(), RequestSpec{
		URL:         "not-a-url",
		Method:      "POST",
		ContentType: "application/json",
	})
	if res.Error == "" {
		t.Fatal("expected error for invalid url")
	}
}
