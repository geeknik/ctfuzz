package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"ctfuzz/internal/render"
)

const (
	DefaultOutput         = "ctfuzz-results.jsonl"
	DefaultConcurrency    = 8
	DefaultTimeout        = 10 * time.Second
	DefaultDelay          = 0
	DefaultMaxBodyRead    = 65536
	DefaultMaxRequestBody = 65536
)

type Config struct {
	URLsFile           string
	PayloadFile        string
	HeadersFile        string
	OutputFile         string
	ScopeFile          string
	AllowScopeDrops    bool
	DryRun             bool
	MaxRequestsPerHost int
	CanaryPrefix       string
	Method             string
	Methods            []string
	Mismatch           bool
	Concurrency        int
	Timeout            time.Duration
	Delay              time.Duration
	Proxy              string
	Insecure           bool
	FollowRedirects    bool
	MaxBodyRead        int64
	MaxRequestBody     int64
	IncludeBody        bool
	Types              []string
	Canary             string
	Verbose            bool
	Retries            int
	RetryBackoff       time.Duration
	RequestsPerSecond  float64
}

func Parse(args []string, output io.Writer) (Config, error) {
	cfg := Config{
		OutputFile:     DefaultOutput,
		Method:         "POST",
		Concurrency:    DefaultConcurrency,
		Timeout:        DefaultTimeout,
		Delay:          DefaultDelay,
		MaxBodyRead:    DefaultMaxBodyRead,
		MaxRequestBody: DefaultMaxRequestBody,
		Canary:         "random",
		Retries:        0,
		RetryBackoff:   250 * time.Millisecond,
	}
	var rawTypes string

	fs := flag.NewFlagSet("ctfuzz", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.StringVar(&cfg.URLsFile, "urls", "", "file containing one target URL per line")
	fs.StringVar(&cfg.PayloadFile, "payload", "", "base JSON object payload file")
	fs.StringVar(&cfg.HeadersFile, "headers", "", "static HTTP headers file")
	fs.StringVar(&cfg.OutputFile, "out", DefaultOutput, "JSONL output file")
	fs.StringVar(&cfg.Method, "method", "POST", "single HTTP method (use --methods for a comma list)")
	var rawMethods string
	fs.StringVar(&rawMethods, "methods", "", "comma-separated HTTP methods; overrides --method when set (e.g. POST,PUT,PATCH,DELETE,GET)")
	fs.BoolVar(&cfg.Mismatch, "mismatch", false, "additive mismatch mode: send body/Content-Type disagreements (json-as-xml, form-no-header, etc.)")
	fs.IntVar(&cfg.Concurrency, "concurrency", DefaultConcurrency, "parallel workers")
	fs.DurationVar(&cfg.Timeout, "timeout", DefaultTimeout, "per-request timeout")
	fs.DurationVar(&cfg.Delay, "delay", DefaultDelay, "delay between requests per worker")
	fs.StringVar(&cfg.Proxy, "proxy", "", "HTTP, HTTPS, SOCKS5, or SOCKS5H proxy URL")
	fs.BoolVar(&cfg.Insecure, "insecure", false, "skip TLS certificate verification")
	fs.BoolVar(&cfg.FollowRedirects, "follow-redirects", false, "follow HTTP redirects")
	fs.Int64Var(&cfg.MaxBodyRead, "max-body-read", DefaultMaxBodyRead, "maximum response bytes to fingerprint")
	fs.Int64Var(&cfg.MaxRequestBody, "max-request-body", DefaultMaxRequestBody, "maximum rendered request body bytes")
	fs.BoolVar(&cfg.IncludeBody, "include-body", false, "write truncated response bodies to JSONL")
	fs.StringVar(&rawTypes, "types", "all", "comma-separated content types: "+render.TypeHelp)
	fs.StringVar(&cfg.Canary, "canary", "random", "canary value to inject; use random or none")
	fs.StringVar(&cfg.CanaryPrefix, "canary-prefix", "", "optional fixed prefix prepended to the random canary (empty for an unfingerprintable token)")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "print every request result")
	fs.IntVar(&cfg.Retries, "retries", 0, "retries per request on network errors only")
	fs.DurationVar(&cfg.RetryBackoff, "retry-backoff", 250*time.Millisecond, "base backoff between retries; exponential with jitter")
	fs.Float64Var(&cfg.RequestsPerSecond, "rps", 0, "per-host requests-per-second cap; 0 disables rate limiting")
	fs.StringVar(&cfg.ScopeFile, "scope-file", "", "file of allowlisted hosts (exact or *.wildcard); URLs outside scope are dropped and the run aborts unless --allow-scope-drops is set")
	fs.BoolVar(&cfg.AllowScopeDrops, "allow-scope-drops", false, "continue with a warning when --scope-file filters URLs; default is to abort")
	fs.BoolVar(&cfg.DryRun, "dry-run", false, "plan only: print the request matrix and exit without sending any requests")
	fs.IntVar(&cfg.MaxRequestsPerHost, "max-requests-per-host", 0, "hard cap on total requests sent to any single host; 0 disables")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected positional argument %q", fs.Arg(0))
	}

	types, err := parseTypes(rawTypes)
	if err != nil {
		return Config{}, err
	}
	cfg.Types = types

	methods, err := parseMethods(rawMethods, cfg.Method)
	if err != nil {
		return Config{}, err
	}
	cfg.Methods = methods

	if err := cfg.normalize(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func parseMethods(raw, singular string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		m := strings.ToUpper(strings.TrimSpace(singular))
		if !allowedMethod(m) {
			return nil, fmt.Errorf("unsupported HTTP method %q", singular)
		}
		return []string{m}, nil
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		m := strings.ToUpper(strings.TrimSpace(part))
		if m == "" {
			return nil, errors.New("--methods contains an empty item")
		}
		if !allowedMethod(m) {
			return nil, fmt.Errorf("unsupported HTTP method %q", part)
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, errors.New("--methods must include at least one method")
	}
	return out, nil
}

func (c *Config) normalize() error {
	if strings.TrimSpace(c.URLsFile) == "" {
		return errors.New("--urls is required")
	}
	if strings.TrimSpace(c.PayloadFile) == "" {
		return errors.New("--payload is required")
	}

	method := strings.ToUpper(strings.TrimSpace(c.Method))
	if !allowedMethod(method) {
		return fmt.Errorf("unsupported HTTP method %q", c.Method)
	}
	c.Method = method

	if c.Concurrency < 1 || c.Concurrency > 64 {
		return errors.New("--concurrency must be between 1 and 64")
	}
	if c.Timeout <= 0 || c.Timeout > 5*time.Minute {
		return errors.New("--timeout must be greater than 0 and at most 5m")
	}
	if c.Delay < 0 || c.Delay > time.Minute {
		return errors.New("--delay must be between 0 and 1m")
	}
	if c.MaxBodyRead < 0 || c.MaxBodyRead > 16*1024*1024 {
		return errors.New("--max-body-read must be between 0 and 16777216")
	}
	if c.MaxRequestBody <= 0 || c.MaxRequestBody > 1024*1024 {
		return errors.New("--max-request-body must be greater than 0 and at most 1048576")
	}
	if c.Retries < 0 || c.Retries > 10 {
		return errors.New("--retries must be between 0 and 10")
	}
	if c.RetryBackoff < 0 || c.RetryBackoff > 30*time.Second {
		return errors.New("--retry-backoff must be between 0 and 30s")
	}
	if c.RequestsPerSecond < 0 || c.RequestsPerSecond > 1000 {
		return errors.New("--rps must be between 0 and 1000")
	}
	if c.MaxRequestsPerHost < 0 || c.MaxRequestsPerHost > 1_000_000 {
		return errors.New("--max-requests-per-host must be between 0 and 1000000")
	}
	if len(c.CanaryPrefix) > 64 {
		return errors.New("--canary-prefix must be 64 bytes or fewer")
	}
	if strings.ContainsAny(c.CanaryPrefix, "\r\n\t\x00 ") {
		return errors.New("--canary-prefix must not contain whitespace or control characters")
	}
	if c.Proxy != "" {
		if err := validateProxy(c.Proxy); err != nil {
			return err
		}
	}
	if c.OutputFile == "" {
		return errors.New("--out must not be empty")
	}

	switch c.Canary {
	case "random":
		canary, err := randomCanary(c.CanaryPrefix)
		if err != nil {
			return err
		}
		c.Canary = canary
	case "none":
		c.Canary = ""
	default:
		if strings.ContainsAny(c.Canary, "\r\n\t\x00") {
			return errors.New("--canary must not contain control characters")
		}
		if len(c.Canary) > 256 {
			return errors.New("--canary must be 256 bytes or fewer")
		}
	}
	return nil
}

func allowedMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func parseTypes(raw string) ([]string, error) {
	return render.ResolveTypes(raw)
}

func validateProxy(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid --proxy URL: %w", err)
	}
	if u.Host == "" {
		return errors.New("--proxy must include a host")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
		return nil
	default:
		return errors.New("--proxy scheme must be http, https, socks5, or socks5h")
	}
}

func randomCanary(prefix string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("failed to generate canary")
	}
	return prefix + hex.EncodeToString(b[:]), nil
}
