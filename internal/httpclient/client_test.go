package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientBlocksOutOfScopeRedirect(t *testing.T) {
	var targetHits, leakHits atomic.Int32
	leak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leakHits.Add(1)
		_, _ = w.Write([]byte("leaked"))
	}))
	defer leak.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		http.Redirect(w, r, leak.URL+"/", http.StatusFound)
	}))
	defer target.Close()

	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatalf("parse target url: %v", err)
	}

	c, err := New(Config{
		Timeout:         2 * time.Second,
		MaxBodyRead:     4096,
		FollowRedirects: true,
		Retries:         2,
		RetryBackoff:    5 * time.Millisecond,
		AllowRedirect: func(u *url.URL) bool {
			return u.Host == targetURL.Host
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	res := c.Do(context.Background(), RequestSpec{
		URL:         target.URL + "/",
		Method:      "POST",
		ContentType: "application/json",
		Body:        []byte("{}"),
	})

	if got := leakHits.Load(); got != 0 {
		t.Fatalf("out-of-scope redirect target was hit %d time(s)", got)
	}
	if got := targetHits.Load(); got != 1 {
		t.Fatalf("scope-blocked redirect must not be retried; target hit %d times", got)
	}
	if res.Error != "redirect out of scope" {
		t.Fatalf("expected error %q, got %q", "redirect out of scope", res.Error)
	}
	if res.Status != http.StatusFound {
		t.Fatalf("expected blocked hop to record status 302, got %d", res.Status)
	}
	if res.RedirectLocation != leak.URL+"/" {
		t.Fatalf("expected blocked hop to record Location, got %q", res.RedirectLocation)
	}
}

func TestClientFollowsRedirectWithoutPolicy(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("final"))
	}))
	defer final.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/", http.StatusFound)
	}))
	defer target.Close()

	c, err := New(Config{
		Timeout:         2 * time.Second,
		MaxBodyRead:     4096,
		FollowRedirects: true,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	res := c.Do(context.Background(), RequestSpec{
		URL:         target.URL + "/",
		Method:      "POST",
		ContentType: "application/json",
		Body:        []byte("{}"),
	})
	if res.Error != "" {
		t.Fatalf("expected redirect without policy to be followed, got error=%q", res.Error)
	}
	if res.Status != http.StatusOK {
		t.Fatalf("expected final status 200, got %d", res.Status)
	}
}

func TestClientBlocksOutOfScopeRedirectAfterInScopeHop(t *testing.T) {
	// A (in scope) -> B (in scope) -> leak (out of scope): the chain must be
	// gated per hop, not just on the first Location.
	var leakHits atomic.Int32
	leak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leakHits.Add(1)
		_, _ = w.Write([]byte("leaked"))
	}))
	defer leak.Close()

	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, leak.URL+"/", http.StatusFound)
	}))
	defer b.Close()

	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, b.URL+"/", http.StatusFound)
	}))
	defer a.Close()

	aURL, err := url.Parse(a.URL)
	if err != nil {
		t.Fatalf("parse a url: %v", err)
	}
	bURL, err := url.Parse(b.URL)
	if err != nil {
		t.Fatalf("parse b url: %v", err)
	}
	inScope := map[string]struct{}{aURL.Host: {}, bURL.Host: {}}

	c, err := New(Config{
		Timeout:         2 * time.Second,
		MaxBodyRead:     4096,
		FollowRedirects: true,
		AllowRedirect: func(u *url.URL) bool {
			_, ok := inScope[u.Host]
			return ok
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	res := c.Do(context.Background(), RequestSpec{
		URL:         a.URL + "/",
		Method:      "POST",
		ContentType: "application/json",
		Body:        []byte("{}"),
	})

	if got := leakHits.Load(); got != 0 {
		t.Fatalf("out-of-scope final hop was hit %d time(s)", got)
	}
	if res.Error != "redirect out of scope" {
		t.Fatalf("expected error %q, got %q", "redirect out of scope", res.Error)
	}
	if res.Status != http.StatusFound || res.RedirectLocation != leak.URL+"/" {
		t.Fatalf("expected blocked row to record B's 302 and Location, got status=%d location=%q",
			res.Status, res.RedirectLocation)
	}
}

func TestClientBlocksOutOfScope307Redirect(t *testing.T) {
	// 307 preserves method and body across the hop; the block must fire
	// before that re-issued request reaches the out-of-scope host.
	var leakHits atomic.Int32
	var leakSawBody atomic.Int32
	leak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leakHits.Add(1)
		if r.Method == http.MethodPost && r.ContentLength > 0 {
			leakSawBody.Add(1)
		}
		_, _ = w.Write([]byte("leaked"))
	}))
	defer leak.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, leak.URL+"/", http.StatusTemporaryRedirect)
	}))
	defer target.Close()

	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatalf("parse target url: %v", err)
	}

	c, err := New(Config{
		Timeout:         2 * time.Second,
		MaxBodyRead:     4096,
		FollowRedirects: true,
		AllowRedirect:   func(u *url.URL) bool { return u.Host == targetURL.Host },
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	res := c.Do(context.Background(), RequestSpec{
		URL:         target.URL + "/",
		Method:      "POST",
		ContentType: "application/json",
		Body:        []byte(`{"k":"v"}`),
	})

	if got := leakHits.Load(); got != 0 {
		t.Fatalf("out-of-scope 307 target was hit %d time(s) (body seen: %d)", got, leakSawBody.Load())
	}
	if res.Error != "redirect out of scope" {
		t.Fatalf("expected error %q, got %q", "redirect out of scope", res.Error)
	}
	if res.Status != http.StatusTemporaryRedirect {
		t.Fatalf("expected blocked row to record status 307, got %d", res.Status)
	}
}

func TestRateLimiterPacesRedirectHops(t *testing.T) {
	// rps=1, burst=1: the original request drains the host's only token, so
	// a redirect hop back to the same host must wait ~1s for the next one.
	// Pre-fix, hops bypassed the limiter entirely and the chain was instant.
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/landed", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c, err := New(Config{
		Timeout:           5 * time.Second,
		MaxBodyRead:       1024,
		FollowRedirects:   true,
		RequestsPerSecond: 1,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	start := time.Now()
	res := c.Do(context.Background(), RequestSpec{
		URL:         server.URL + "/start",
		Method:      "POST",
		ContentType: "application/json",
		Body:        []byte("{}"),
	})
	elapsed := time.Since(start)

	if res.Error != "" {
		t.Fatalf("expected redirect chain to complete, got error=%q", res.Error)
	}
	if res.Status != http.StatusOK {
		t.Fatalf("expected final status 200, got %d", res.Status)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("expected 2 server hits (start + hop), got %d", got)
	}
	if elapsed < 400*time.Millisecond {
		t.Fatalf("redirect hop bypassed the rate limiter: chain finished in %v, want >= 400ms", elapsed)
	}
}

func TestRateLimiterBucketsArePerHostnameNotPort(t *testing.T) {
	// The docs and --max-requests-per-host treat "host" as the hostname;
	// the limiter must too, so two ports on the same host share one bucket
	// instead of each getting a fresh burst.
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s1.Close()
	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s2.Close()

	c, err := New(Config{
		Timeout:           5 * time.Second,
		MaxBodyRead:       1024,
		RequestsPerSecond: 1, // burst 1
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	res1 := c.Do(context.Background(), RequestSpec{URL: s1.URL + "/a", Method: "POST", ContentType: "application/json", Body: []byte("{}")})
	if res1.Error != "" {
		t.Fatalf("first request: %q", res1.Error)
	}

	start := time.Now()
	res2 := c.Do(context.Background(), RequestSpec{URL: s2.URL + "/b", Method: "POST", ContentType: "application/json", Body: []byte("{}")})
	elapsed := time.Since(start)

	if res2.Error != "" {
		t.Fatalf("second request: %q", res2.Error)
	}
	if elapsed < 400*time.Millisecond {
		t.Fatalf("same-hostname different-port request got a fresh bucket (finished in %v); buckets must key on hostname", elapsed)
	}
}

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
