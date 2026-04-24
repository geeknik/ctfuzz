package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	if err := run([]string{
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
	URL          string               `json:"url"`
	Kind         string               `json:"kind"`
	Interesting  bool                 `json:"interesting"`
	Score        int                  `json:"score"`
	HeaderGroups []fullHeaderGroup    `json:"header_groups"`
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

	if err := run([]string{
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
