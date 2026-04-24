package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ctfuzz/internal/fingerprint"
	"ctfuzz/internal/result"
)

type Config struct {
	Timeout           time.Duration
	Proxy             string
	Insecure          bool
	FollowRedirects   bool
	MaxBodyRead       int64
	IncludeBody       bool
	Canary            string
	Retries           int
	RetryBackoff      time.Duration
	RequestsPerSecond float64
}

type Client struct {
	httpClient   *http.Client
	timeout      time.Duration
	maxBodyRead  int64
	includeBody  bool
	canary       string
	retries      int
	retryBackoff time.Duration
	limiter      *hostLimiter
}

type RequestSpec struct {
	Seq         int
	URL         string
	Method      string
	ContentType string
	OmitCT      bool
	Body        []byte
	Headers     http.Header
}

func New(cfg Config) (*Client, error) {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
	}
	if cfg.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{Transport: transport}
	if !cfg.FollowRedirects {
		client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		}
	}

	retries := cfg.Retries
	if retries < 0 {
		retries = 0
	}
	backoff := cfg.RetryBackoff
	if backoff <= 0 {
		backoff = 250 * time.Millisecond
	}

	return &Client{
		httpClient:   client,
		timeout:      cfg.Timeout,
		maxBodyRead:  cfg.MaxBodyRead,
		includeBody:  cfg.IncludeBody,
		canary:       cfg.Canary,
		retries:      retries,
		retryBackoff: backoff,
		limiter:      newHostLimiter(cfg.RequestsPerSecond),
	}, nil
}

func (c *Client) Do(parent context.Context, spec RequestSpec) result.Request {
	header := result.Request{
		Seq:         spec.Seq,
		URL:         spec.URL,
		Method:      spec.Method,
		ContentType: spec.ContentType,
	}

	reqURL, err := url.Parse(spec.URL)
	if err != nil || reqURL.Host == "" {
		header.Error = "invalid target url"
		return header
	}
	host := strings.ToLower(reqURL.Host)

	attempts := c.retries + 1
	var last result.Request
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			wait := jitteredBackoff(c.retryBackoff, attempt)
			if !sleepCtx(parent, wait) {
				last.Error = "request canceled"
				return merge(header, last)
			}
		}
		if err := c.limiter.Acquire(parent, host); err != nil {
			last.Error = "request canceled"
			return merge(header, last)
		}

		res, retryable := c.attempt(parent, spec)
		last = res
		if !retryable || attempt+1 >= attempts {
			return merge(header, res)
		}
	}
	return merge(header, last)
}

func (c *Client) attempt(parent context.Context, spec RequestSpec) (result.Request, bool) {
	var res result.Request

	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, spec.Method, spec.URL, bytes.NewReader(spec.Body))
	if err != nil {
		res.Error = "request creation failed"
		return res, false
	}
	applyHeaders(req, spec.Headers, spec.ContentType, spec.OmitCT)

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	res.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = classifyRequestError(err)
		return res, isRetryableErr(err)
	}
	defer resp.Body.Close()

	res.Status = resp.StatusCode
	res.RedirectLocation = resp.Header.Get("Location")
	res.HeaderSHA256 = fingerprint.HeaderSHA256(resp.Header)
	res.ResponseHeaders = fingerprint.ExtractTriageHeaders(resp.Header)

	body, truncated, readErr := readLimited(resp.Body, c.maxBodyRead)
	if readErr != nil {
		res.Error = "response read failed"
		return res, isRetryableErr(readErr)
	}
	res.BodyTruncated = truncated
	res.ResponseLen = int64(len(body))
	res.BodySHA256 = fingerprint.SHA256(body)
	res.ErrorKeyword = fingerprint.ContainsErrorKeyword(body)
	if c.canary != "" {
		res.CanaryReflected = bytes.Contains(body, []byte(c.canary))
	}
	if c.includeBody {
		res.Body = string(body)
	}
	return res, false
}

func applyHeaders(req *http.Request, headers http.Header, contentType string, omitCT bool) {
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "ctfuzz/0.1")
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "*/*")
	}
	if omitCT {
		req.Header.Del("Content-Type")
		return
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
}

func readLimited(r io.Reader, maxBytes int64) ([]byte, bool, error) {
	if maxBytes == 0 {
		return nil, false, nil
	}
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maxBytes {
		return data[:maxBytes], true, nil
	}
	return data, false, nil
}

func classifyRequestError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "request timed out"
	}
	if strings.Contains(strings.ToLower(err.Error()), "timeout") {
		return "request timed out"
	}
	return "request failed"
}

func isRetryableErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := strings.ToLower(err.Error())
	retryable := []string{
		"connection reset",
		"connection refused",
		"broken pipe",
		"no such host",
		"i/o timeout",
		"tls handshake",
		"eof",
		"server closed",
	}
	for _, s := range retryable {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func merge(header, body result.Request) result.Request {
	out := body
	out.Seq = header.Seq
	out.URL = header.URL
	out.Method = header.Method
	out.ContentType = header.ContentType
	return out
}
