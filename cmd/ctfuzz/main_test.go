package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ctfuzz/internal/config"
	"ctfuzz/internal/payload"
	"ctfuzz/internal/render"
)

func TestHeaderClusteringSurfacesDeltaEndToEnd(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Refuse POST uniformly (405) but cluster response headers by CT family.
		// JSON family → one set; everything else → another.
		ct := r.Header.Get("Content-Type")
		if strings.Contains(ct, "json") {
			w.Header().Set("Vary", "Accept")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Server", "clusterd")
		} else {
			w.Header().Set("Vary", "Accept, Accept-Encoding")
			w.Header().Set("Server", "clusterd")
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer server.Close()

	dir := t.TempDir()
	urlsPath := filepath.Join(dir, "urls.txt")
	payloadPath := filepath.Join(dir, "payload.json")
	outPath := filepath.Join(dir, "out.jsonl")

	if err := os.WriteFile(urlsPath, []byte(server.URL+"/edge\n"), 0600); err != nil {
		t.Fatalf("write urls: %v", err)
	}
	if err := os.WriteFile(payloadPath, []byte(`{"id":"1","name":"ctfuzz"}`), 0600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	if _, err := run([]string{
		"--urls", urlsPath,
		"--payload", payloadPath,
		"--out", outPath,
		"--concurrency", "2",
		"--timeout", "2s",
		"--types", "all",
		"--canary", "none",
	}); err != nil {
		t.Fatalf("run: %v", err)
	}

	summaries := readRawSummaries(t, outPath)
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	summary := summaries[0]
	if !summary.Interesting {
		t.Fatalf("expected structural cluster to be flagged interesting, got %+v", summary)
	}
	if len(summary.HeaderGroups) != 2 {
		t.Fatalf("expected 2 header groups, got %d", len(summary.HeaderGroups))
	}
	diffNames := map[string]bool{}
	for _, g := range summary.HeaderGroups {
		for name := range g.Headers {
			diffNames[name] = true
		}
	}
	if !diffNames["Vary"] || !diffNames["X-Frame-Options"] {
		t.Fatalf("expected Vary and X-Frame-Options in differing headers, got %v", diffNames)
	}
	if diffNames["Server"] {
		t.Fatalf("Server was identical across groups and must not appear as differing: %v", diffNames)
	}
}

type fullSummary struct {
	URL          string            `json:"url"`
	Method       string            `json:"method"`
	Kind         string            `json:"kind"`
	Interesting  bool              `json:"interesting"`
	Score        int               `json:"score"`
	HeaderGroups []fullHeaderGroup `json:"header_groups"`
}

type fullHeaderGroup struct {
	Hash         string            `json:"hash"`
	ContentTypes []string          `json:"content_types"`
	Headers      map[string]string `json:"headers"`
}

func readRawSummaries(t *testing.T, path string) []fullSummary {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	out := []fullSummary{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var raw map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if raw["kind"] != "summary" {
			continue
		}
		var s fullSummary
		if err := json.Unmarshal(scanner.Bytes(), &s); err != nil {
			t.Fatalf("decode summary: %v", err)
		}
		out = append(out, s)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}

func TestMethodsMatrixSplitsSummariesByMethod(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			w.WriteHeader(http.StatusForbidden)
		case "PUT":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("put-accepted"))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	urlsPath := filepath.Join(dir, "urls.txt")
	payloadPath := filepath.Join(dir, "payload.json")
	outPath := filepath.Join(dir, "out.jsonl")
	_ = os.WriteFile(urlsPath, []byte(server.URL+"/e\n"), 0600)
	_ = os.WriteFile(payloadPath, []byte(`{"id":"1"}`), 0600)

	if _, err := run([]string{
		"--urls", urlsPath,
		"--payload", payloadPath,
		"--out", outPath,
		"--types", "core",
		"--methods", "POST,PUT",
		"--concurrency", "2",
		"--timeout", "2s",
		"--canary", "none",
	}); err != nil {
		t.Fatalf("run: %v", err)
	}

	summaries := readRawSummaries(t, outPath)
	if len(summaries) != 2 {
		t.Fatalf("expected 2 summaries (POST, PUT), got %d", len(summaries))
	}
	byMethod := map[string]fullSummary{}
	for _, s := range summaries {
		byMethod[s.Method] = s
	}
	if byMethod["POST"].Method != "POST" {
		t.Fatalf("expected POST summary present, got %#v", summaries)
	}
	if byMethod["PUT"].Method != "PUT" {
		t.Fatalf("expected PUT summary present, got %#v", summaries)
	}
	// PUT returned 200 uniformly, POST returned 403 uniformly; neither should be
	// "interesting" on its own since it's not a differential within the method.
	if byMethod["POST"].Interesting || byMethod["PUT"].Interesting {
		t.Fatalf("expected uniform-status summaries to be uninteresting: %#v", summaries)
	}
}

func TestMismatchAddsVariantsAndTagsBodyEncoding(t *testing.T) {
	var seen struct {
		mu        sync.Mutex
		variants  map[string]int
		bodies    map[string]string
		noCTCount int
	}
	seen.variants = map[string]int{}
	seen.bodies = map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		seen.mu.Lock()
		ct := r.Header.Get("Content-Type")
		seen.variants[ct]++
		seen.bodies[ct] = string(buf)
		if ct == "" {
			seen.noCTCount++
		}
		seen.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dir := t.TempDir()
	urlsPath := filepath.Join(dir, "urls.txt")
	payloadPath := filepath.Join(dir, "payload.json")
	outPath := filepath.Join(dir, "out.jsonl")
	_ = os.WriteFile(urlsPath, []byte(server.URL+"/m\n"), 0600)
	_ = os.WriteFile(payloadPath, []byte(`{"id":"1"}`), 0600)

	if _, err := run([]string{
		"--urls", urlsPath,
		"--payload", payloadPath,
		"--out", outPath,
		"--types", "core",
		"--mismatch",
		"--concurrency", "2",
		"--timeout", "2s",
		"--canary", "none",
	}); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Read request lines (not summaries) and confirm BodyEncoding + VariantName
	// were populated.
	f, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	mismatchSeen := 0
	noCTSeen := 0
	for scanner.Scan() {
		var raw map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if raw["kind"] == "summary" {
			continue
		}
		variant, _ := raw["variant"].(string)
		if strings.Contains(variant, "-as-") || strings.Contains(variant, "-no-header") {
			mismatchSeen++
		}
		if variant == "json-no-header" || variant == "form-no-header" {
			noCTSeen++
		}
	}
	if mismatchSeen < len(render.MismatchScenarios) {
		t.Fatalf("expected %d mismatch variants in output, got %d", len(render.MismatchScenarios), mismatchSeen)
	}
	if noCTSeen < 2 {
		t.Fatalf("expected 2 no-header variants, got %d", noCTSeen)
	}
	if seen.noCTCount < 2 {
		t.Fatalf("expected server to see 2 requests without Content-Type, saw %d", seen.noCTCount)
	}
}

func TestScopeFileAbortsByDefault(t *testing.T) {
	dir := t.TempDir()
	urlsPath := filepath.Join(dir, "urls.txt")
	scopePath := filepath.Join(dir, "scope.txt")
	payloadPath := filepath.Join(dir, "payload.json")
	outPath := filepath.Join(dir, "out.jsonl")

	body := "https://in-scope.example.com/a\nhttps://out-of-scope.attacker.test/x\n"
	if err := os.WriteFile(urlsPath, []byte(body), 0600); err != nil {
		t.Fatalf("write urls: %v", err)
	}
	if err := os.WriteFile(scopePath, []byte("in-scope.example.com\n"), 0600); err != nil {
		t.Fatalf("write scope: %v", err)
	}
	if err := os.WriteFile(payloadPath, []byte(`{"k":"v"}`), 0600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	_, err := run([]string{
		"--urls", urlsPath,
		"--scope-file", scopePath,
		"--payload", payloadPath,
		"--out", outPath,
		"--dry-run",
	})
	if err == nil {
		t.Fatal("expected scope violation error")
	}
	if !errors.Is(err, errScopeViolation) {
		t.Fatalf("expected errScopeViolation, got %v", err)
	}
}

func TestScopeFileContinuesWithAllowDrops(t *testing.T) {
	dir := t.TempDir()
	urlsPath := filepath.Join(dir, "urls.txt")
	scopePath := filepath.Join(dir, "scope.txt")
	payloadPath := filepath.Join(dir, "payload.json")
	outPath := filepath.Join(dir, "out.jsonl")

	body := "https://in-scope.example.com/a\nhttps://out-of-scope.attacker.test/x\n"
	_ = os.WriteFile(urlsPath, []byte(body), 0600)
	_ = os.WriteFile(scopePath, []byte("in-scope.example.com\n"), 0600)
	_ = os.WriteFile(payloadPath, []byte(`{"k":"v"}`), 0600)

	if _, err := run([]string{
		"--urls", urlsPath,
		"--scope-file", scopePath,
		"--allow-scope-drops",
		"--payload", payloadPath,
		"--out", outPath,
		"--dry-run",
	}); err != nil {
		t.Fatalf("expected dry-run with scope drops to succeed: %v", err)
	}
}

func TestDryRunSkipsNetwork(t *testing.T) {
	// httptest server that fails the test if hit.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("network call during dry run to %s", r.URL.Path)
	}))
	defer server.Close()

	dir := t.TempDir()
	urlsPath := filepath.Join(dir, "urls.txt")
	payloadPath := filepath.Join(dir, "payload.json")
	outPath := filepath.Join(dir, "out.jsonl")
	_ = os.WriteFile(urlsPath, []byte(server.URL+"/foo\n"), 0600)
	_ = os.WriteFile(payloadPath, []byte(`{"k":"v"}`), 0600)

	if _, err := run([]string{
		"--urls", urlsPath,
		"--payload", payloadPath,
		"--out", outPath,
		"--dry-run",
	}); err != nil {
		t.Fatalf("dry-run failed: %v", err)
	}
	if _, err := os.Stat(outPath); err == nil {
		t.Fatal("dry-run should not write results file")
	}
}

func TestMaxRequestsPerHostCapsVolume(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dir := t.TempDir()
	urlsPath := filepath.Join(dir, "urls.txt")
	payloadPath := filepath.Join(dir, "payload.json")
	outPath := filepath.Join(dir, "out.jsonl")
	_ = os.WriteFile(urlsPath, []byte(server.URL+"/a\n"+server.URL+"/b\n"), 0600)
	_ = os.WriteFile(payloadPath, []byte(`{"k":"v"}`), 0600)

	if _, err := run([]string{
		"--urls", urlsPath,
		"--payload", payloadPath,
		"--out", outPath,
		"--types", "core",
		"--max-requests-per-host", "4",
		"--concurrency", "2",
		"--timeout", "2s",
		"--canary", "none",
	}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := attempts.Load(); got != 4 {
		t.Fatalf("expected 4 requests under per-host cap, got %d", got)
	}
}

func TestCanaryPrefixDefaultHasNoCtfuzzTell(t *testing.T) {
	dir := t.TempDir()
	urlsPath := filepath.Join(dir, "urls.txt")
	payloadPath := filepath.Join(dir, "payload.json")
	outPath := filepath.Join(dir, "out.jsonl")
	_ = os.WriteFile(urlsPath, []byte("https://in-scope.example.com/a\n"), 0600)
	_ = os.WriteFile(payloadPath, []byte(`{"k":"v"}`), 0600)

	// --dry-run so no network; we inspect canary via payload load path.
	// Run parse alone to verify the resolved canary.
	cfg, err := configParseFor([]string{
		"--urls", urlsPath,
		"--payload", payloadPath,
		"--out", outPath,
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if strings.HasPrefix(cfg.Canary, "ctfuzz_") {
		t.Fatalf("canary default should not leak the ctfuzz_ prefix: %q", cfg.Canary)
	}
	if len(cfg.Canary) < 16 {
		t.Fatalf("default random canary should be ≥16 hex chars: %q", cfg.Canary)
	}
}

func TestCanaryPrefixRespectsFlag(t *testing.T) {
	dir := t.TempDir()
	urlsPath := filepath.Join(dir, "urls.txt")
	payloadPath := filepath.Join(dir, "payload.json")
	_ = os.WriteFile(urlsPath, []byte("https://in-scope.example.com/a\n"), 0600)
	_ = os.WriteFile(payloadPath, []byte(`{"k":"v"}`), 0600)

	cfg, err := configParseFor([]string{
		"--urls", urlsPath,
		"--payload", payloadPath,
		"--canary-prefix", "markerx_",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !strings.HasPrefix(cfg.Canary, "markerx_") {
		t.Fatalf("expected prefix honored, got %q", cfg.Canary)
	}
}

func configParseFor(args []string) (config.Config, error) {
	return config.Parse(args, os.Stderr)
}

func TestShippedPayloadLoadsAndRenders(t *testing.T) {
	shipped := filepath.Join("..", "..", "payload.json")
	obj, err := payload.Load(shipped, 65536, "ctfuzz_test")
	if err != nil {
		t.Fatalf("shipped payload.json did not load cleanly: %v", err)
	}
	if len(obj) < 3 {
		t.Fatalf("shipped payload is suspiciously small: %d keys", len(obj))
	}
	for _, ct := range render.AllContentTypes {
		body, err := render.Body(ct, obj)
		if err != nil {
			t.Fatalf("render %s from shipped payload: %v", ct, err)
		}
		if len(body) == 0 {
			t.Fatalf("rendered %s body was empty", ct)
		}
	}
}

func TestRunEndToEndAgainstDifferentialServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		switch r.URL.Path {
		case "/same":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("same"))
		case "/json-only":
			if contentType == "application/json" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("json ok"))
				return
			}
			w.WriteHeader(http.StatusUnsupportedMediaType)
		case "/form-bypass":
			if contentType == "application/x-www-form-urlencoded" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("form accepted with extra data"))
				return
			}
			w.WriteHeader(http.StatusForbidden)
		case "/xml-error":
			if contentType == "application/xml" {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("xml parser fatal error"))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		case "/reflect":
			w.WriteHeader(http.StatusOK)
			if contentType == "application/xml" {
				_, _ = w.Write([]byte("ctfuzz_FIXED"))
				return
			}
			_, _ = w.Write([]byte("ok"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	urlsPath := filepath.Join(dir, "urls.txt")
	payloadPath := filepath.Join(dir, "payload.json")
	outPath := filepath.Join(dir, "out.jsonl")

	urls := server.URL + "/same\n" +
		server.URL + "/json-only\n" +
		server.URL + "/form-bypass\n" +
		server.URL + "/xml-error\n" +
		server.URL + "/reflect\n"
	if err := os.WriteFile(urlsPath, []byte(urls), 0600); err != nil {
		t.Fatalf("write urls: %v", err)
	}
	if err := os.WriteFile(payloadPath, []byte(`{"id":"1","name":"ctfuzz"}`), 0600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	if _, err := run([]string{
		"--urls", urlsPath,
		"--payload", payloadPath,
		"--out", outPath,
		"--concurrency", "2",
		"--timeout", "2s",
		"--canary", "ctfuzz_FIXED",
	}); err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	summaries := readSummaries(t, outPath)
	expected := map[string]bool{
		server.URL + "/same":        false,
		server.URL + "/json-only":   true,
		server.URL + "/form-bypass": true,
		server.URL + "/xml-error":   true,
		server.URL + "/reflect":     true,
	}
	for targetURL, wantInteresting := range expected {
		got, ok := summaries[targetURL]
		if !ok {
			t.Fatalf("missing summary for %s", targetURL)
		}
		if got.Interesting != wantInteresting {
			t.Fatalf("%s interesting mismatch: got %v want %v summary=%#v", targetURL, got.Interesting, wantInteresting, got)
		}
	}
}

// TestFollowRedirectsRechecksScopeOnEveryHop guards the safety contract that
// --scope-file gates not just the input URLs but every redirect hop when
// --follow-redirects is enabled. The in-scope target is rebound to the
// "localhost" host so the host-based (port-insensitive) scope matcher can
// distinguish it from the leak server's 127.0.0.1.
func TestFollowRedirectsRechecksScopeOnEveryHop(t *testing.T) {
	var leakHits atomic.Int32
	leak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leakHits.Add(1)
		_, _ = w.Write([]byte("leaked"))
	}))
	defer leak.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, leak.URL+"/leaked", http.StatusFound)
	}))
	defer target.Close()

	u, err := url.Parse(target.URL)
	if err != nil {
		t.Fatalf("parse target url: %v", err)
	}
	u.Host = "localhost:" + u.Port()
	targetURL := u.String() + "/api"

	dir := t.TempDir()
	urlsPath := filepath.Join(dir, "urls.txt")
	scopePath := filepath.Join(dir, "scope.txt")
	payloadPath := filepath.Join(dir, "payload.json")
	outPath := filepath.Join(dir, "out.jsonl")

	if err := os.WriteFile(urlsPath, []byte(targetURL+"\n"), 0600); err != nil {
		t.Fatalf("write urls: %v", err)
	}
	if err := os.WriteFile(scopePath, []byte("localhost\n"), 0600); err != nil {
		t.Fatalf("write scope: %v", err)
	}
	if err := os.WriteFile(payloadPath, []byte(`{"k":"v"}`), 0600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	if _, err := run([]string{
		"--urls", urlsPath,
		"--scope-file", scopePath,
		"--payload", payloadPath,
		"--out", outPath,
		"--follow-redirects",
		"--types", "application/json",
		"--timeout", "2s",
	}); err != nil {
		t.Fatalf("run: %v", err)
	}

	if got := leakHits.Load(); got != 0 {
		t.Fatalf("out-of-scope redirect target was hit %d time(s); scope must gate every hop", got)
	}

	type requestRow struct {
		Status           int    `json:"status"`
		RedirectLocation string `json:"redirect_location"`
		Error            string `json:"error"`
	}
	rows := []requestRow{}
	f, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var raw map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
			t.Fatalf("decode jsonl: %v", err)
		}
		if raw["kind"] == "summary" || raw["kind"] == "manifest" {
			continue
		}
		var row requestRow
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatalf("decode request row: %v", err)
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan output: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 request row, got %d", len(rows))
	}
	if rows[0].Error != "redirect out of scope" {
		t.Fatalf("expected error %q, got %q", "redirect out of scope", rows[0].Error)
	}
	if rows[0].Status != http.StatusFound {
		t.Fatalf("expected blocked row to record status 302, got %d", rows[0].Status)
	}
	if rows[0].RedirectLocation != leak.URL+"/leaked" {
		t.Fatalf("expected blocked row to record the redirect location, got %q", rows[0].RedirectLocation)
	}
}

// TestInterruptStopsScanAndFlushesPartialResults pins the graceful-shutdown
// contract: a canceled context stops producing new jobs (no phantom
// "request canceled" rows for work that never started) and the partial
// results still reach --out with an interrupted manifest.
func TestInterruptStopsScanAndFlushesPartialResults(t *testing.T) {
	var hits atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		cancel() // interrupt the scan from inside the first request
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dir := t.TempDir()
	urlsPath := filepath.Join(dir, "urls.txt")
	payloadPath := filepath.Join(dir, "payload.json")
	outPath := filepath.Join(dir, "out.jsonl")

	urls := ""
	for i := 0; i < 5; i++ {
		urls += fmt.Sprintf("%s/endpoint%d\n", server.URL, i)
	}
	if err := os.WriteFile(urlsPath, []byte(urls), 0600); err != nil {
		t.Fatalf("write urls: %v", err)
	}
	if err := os.WriteFile(payloadPath, []byte(`{"k":"v"}`), 0600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	if _, err := runCtx(ctx, []string{
		"--urls", urlsPath,
		"--payload", payloadPath,
		"--out", outPath,
		"--concurrency", "1",
		"--timeout", "2s",
		"--types", "application/json",
		"--canary", "none",
	}, func() {}); err != nil {
		t.Fatalf("runCtx: %v", err)
	}

	if got := hits.Load(); got != 1 {
		t.Fatalf("expected exactly 1 server hit, got %d", got)
	}

	type manifestRow struct {
		Kind        string `json:"kind"`
		Interrupted bool   `json:"interrupted"`
	}
	var manifest manifestRow
	rows := 0
	f, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var raw map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
			t.Fatalf("decode jsonl: %v", err)
		}
		switch raw["kind"] {
		case "manifest":
			if err := json.Unmarshal(scanner.Bytes(), &manifest); err != nil {
				t.Fatalf("decode manifest: %v", err)
			}
		case "summary":
		default:
			rows++
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan output: %v", err)
	}
	if rows != 1 {
		t.Fatalf("expected 1 request row (only the work actually started), got %d", rows)
	}
	if !manifest.Interrupted {
		t.Fatal("expected manifest to record interrupted=true for the partial run")
	}
}

// TestScanFlushesPartialResultsOnSIGINT is the acceptance test for
// graceful shutdown: SIGINT to the real binary must stop the scan, flush
// partial results (manifest interrupted=true), and exit with a normal
// code rather than dying to the default signal handler.
func TestScanFlushesPartialResultsOnSIGINT(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the real binary")
	}

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(400 * time.Millisecond) // keep the scan mid-flight
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	binDir := t.TempDir()
	bin := filepath.Join(binDir, "ctfuzz")
	build := exec.Command("go", "build", "-o", bin, "./cmd/ctfuzz")
	build.Dir = "../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build binary: %v\n%s", err, out)
	}

	dir := t.TempDir()
	urlsPath := filepath.Join(dir, "urls.txt")
	payloadPath := filepath.Join(dir, "payload.json")
	outPath := filepath.Join(dir, "out.jsonl")

	urls := ""
	for i := 0; i < 4; i++ {
		urls += fmt.Sprintf("%s/endpoint%d\n", server.URL, i)
	}
	if err := os.WriteFile(urlsPath, []byte(urls), 0600); err != nil {
		t.Fatalf("write urls: %v", err)
	}
	if err := os.WriteFile(payloadPath, []byte(`{"k":"v"}`), 0600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	proc := exec.Command(bin,
		"--urls", urlsPath,
		"--payload", payloadPath,
		"--out", outPath,
		"--concurrency", "1",
		"--timeout", "5s",
		"--types", "application/json",
		"--canary", "none",
	)
	proc.Stdout = io.Discard
	proc.Stderr = io.Discard
	if err := proc.Start(); err != nil {
		t.Fatalf("start binary: %v", err)
	}

	// Wait until the scan is provably mid-flight (first request entered
	// its 400ms handler sleep), then interrupt.
	deadline := time.Now().Add(10 * time.Second)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hits.Load() == 0 {
		_ = proc.Process.Kill()
		t.Fatal("scan never started; no server hits")
	}
	if err := proc.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("send SIGINT: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- proc.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				t.Fatalf("binary died to the signal instead of shutting down gracefully: %v", exitErr)
			}
			t.Fatalf("wait: %v", err)
		}
	case <-time.After(15 * time.Second):
		_ = proc.Process.Kill()
		t.Fatal("binary did not exit within 15s of SIGINT")
	}

	if got := hits.Load(); got > 2 {
		t.Fatalf("expected at most 2 server hits (1 completed, at most 1 in flight), got %d", got)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("partial results were not written: %v", err)
	}
	lines := []map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("decode jsonl: %v", err)
		}
		lines = append(lines, row)
	}
	if len(lines) < 2 {
		t.Fatalf("expected manifest plus at least one request row, got %d lines", len(lines))
	}
	if lines[0]["kind"] != "manifest" {
		t.Fatalf("first line must be the manifest, got %v", lines[0]["kind"])
	}
	if lines[0]["interrupted"] != true {
		t.Fatal("manifest must record interrupted=true")
	}
	requestRows := 0
	for _, row := range lines[1:] {
		if row["kind"] != "summary" {
			requestRows++
		}
	}
	if requestRows == 0 || requestRows >= 4 {
		t.Fatalf("expected a partial set of request rows (1..3), got %d", requestRows)
	}
}

// TestInterruptDuringFinalRequestsStillFlagsManifest pins the tail window:
// if cancellation lands after the producer has handed off its last job but
// while requests are still in flight (the last --concurrency requests of
// every scan), the run is still partial and the manifest must say so.
func TestInterruptDuringFinalRequestsStillFlagsManifest(t *testing.T) {
	var hits atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/endpoint2" { // final planned request
			cancel()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dir := t.TempDir()
	urlsPath := filepath.Join(dir, "urls.txt")
	payloadPath := filepath.Join(dir, "payload.json")
	outPath := filepath.Join(dir, "out.jsonl")

	urls := ""
	for i := 0; i < 3; i++ {
		urls += fmt.Sprintf("%s/endpoint%d\n", server.URL, i)
	}
	if err := os.WriteFile(urlsPath, []byte(urls), 0600); err != nil {
		t.Fatalf("write urls: %v", err)
	}
	if err := os.WriteFile(payloadPath, []byte(`{"k":"v"}`), 0600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	if _, err := runCtx(ctx, []string{
		"--urls", urlsPath,
		"--payload", payloadPath,
		"--out", outPath,
		"--concurrency", "1",
		"--timeout", "2s",
		"--types", "application/json",
		"--canary", "none",
	}, func() {}); err != nil {
		t.Fatalf("runCtx: %v", err)
	}

	if got := hits.Load(); got != 3 {
		t.Fatalf("expected all 3 requests to start, got %d", got)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var manifest struct {
		Interrupted bool `json:"interrupted"`
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			t.Fatalf("decode jsonl: %v", err)
		}
		if raw["kind"] == "manifest" {
			if err := json.Unmarshal([]byte(line), &manifest); err != nil {
				t.Fatalf("decode manifest: %v", err)
			}
		}
	}
	if !manifest.Interrupted {
		t.Fatal("cancellation during the final in-flight request must still flag the manifest as interrupted")
	}
}

type testSummary struct {
	URL         string `json:"url"`
	Kind        string `json:"kind"`
	Interesting bool   `json:"interesting"`
	Score       int    `json:"score"`
}

func readSummaries(t *testing.T, path string) map[string]testSummary {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer f.Close()

	out := map[string]testSummary{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var raw map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
			t.Fatalf("decode jsonl: %v", err)
		}
		if raw["kind"] != "summary" {
			continue
		}
		var summary testSummary
		if err := json.Unmarshal(scanner.Bytes(), &summary); err != nil {
			t.Fatalf("decode summary: %v", err)
		}
		out[summary.URL] = summary
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan output: %v", err)
	}
	return out
}
