package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runScan executes a scan against a provided handler and returns the path
// to the resulting JSONL.
func runScan(t *testing.T, handler http.HandlerFunc, extraArgs ...string) (dir, jsonlPath string) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	dir = t.TempDir()
	urlsPath := filepath.Join(dir, "urls.txt")
	payloadPath := filepath.Join(dir, "payload.json")
	jsonlPath = filepath.Join(dir, "out.jsonl")
	if err := os.WriteFile(urlsPath, []byte(server.URL+"/api\n"), 0600); err != nil {
		t.Fatalf("write urls: %v", err)
	}
	if err := os.WriteFile(payloadPath, []byte(`{"id":"1"}`), 0600); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	args := append([]string{
		"--urls", urlsPath,
		"--payload", payloadPath,
		"--out", jsonlPath,
		"--types", "core",
		"--canary", "none",
		"--concurrency", "2",
		"--timeout", "2s",
	}, extraArgs...)
	if _, err := run(args); err != nil {
		t.Fatalf("run: %v", err)
	}
	return dir, jsonlPath
}

func TestReplayBySeqPicksOneRequest(t *testing.T) {
	dir, jsonlPath := runScan(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	stdout := captureStdout(t, func() error {
		return runReplay([]string{
			"--jsonl", jsonlPath,
			"--payload", filepath.Join(dir, "payload.json"),
			"--seq", "1",
		})
	})
	// Only the XML variant is at seq=1 (core order is json,xml,form).
	if strings.Count(stdout, "curl") != 1 {
		t.Fatalf("expected exactly one curl command, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Content-Type: application/xml") {
		t.Fatalf("expected XML Content-Type, got:\n%s", stdout)
	}
}

func TestReplayByURLAndMethodFiltersCorrectly(t *testing.T) {
	dir, jsonlPath := runScan(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	stdout := captureStdout(t, func() error {
		return runReplay([]string{
			"--jsonl", jsonlPath,
			"--payload", filepath.Join(dir, "payload.json"),
			"--url", "/api",
			"--method", "POST",
			"--variant", "application/json",
		})
	})
	if strings.Count(stdout, "curl") != 1 {
		t.Fatalf("expected exactly one curl, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, `'{"id":"1"}'`) {
		t.Fatalf("expected JSON body in curl, got:\n%s", stdout)
	}
}

func TestReplayNoMatchErrors(t *testing.T) {
	_, jsonlPath := runScan(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	err := runReplay([]string{"--jsonl", jsonlPath, "--seq", "999"})
	if err == nil {
		t.Fatal("expected error on no match")
	}
}

func TestReportMarkdownContainsFinding(t *testing.T) {
	_, jsonlPath := runScan(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") == "application/json" {
			w.Header().Set("X-Frame-Options", "DENY")
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(403)
	})

	stdout := captureStdout(t, func() error {
		return runReport([]string{"--jsonl", jsonlPath})
	})
	if !strings.Contains(stdout, "# ctfuzz report") {
		t.Fatalf("missing markdown header: %s", stdout)
	}
	if !strings.Contains(stdout, "score:") {
		t.Fatalf("missing score: %s", stdout)
	}
	if !strings.Contains(stdout, "ctfuzz replay") {
		t.Fatalf("missing replay snippet: %s", stdout)
	}
}

func TestReportJSONParsesBack(t *testing.T) {
	_, jsonlPath := runScan(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	stdout := captureStdout(t, func() error {
		return runReport([]string{"--jsonl", jsonlPath, "--format", "json", "--all"})
	})
	var parsed struct {
		Manifest struct {
			Schema int `json:"schema"`
		} `json:"manifest"`
		Summaries []map[string]any `json:"summaries"`
	}
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("json output not parseable: %v\n%s", err, stdout)
	}
	if parsed.Manifest.Schema != 1 {
		t.Fatalf("manifest schema mismatch: %d", parsed.Manifest.Schema)
	}
}

func TestReportMinScoreFilters(t *testing.T) {
	_, jsonlPath := runScan(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200) // uniform → score 0
	})
	stdout := captureStdout(t, func() error {
		return runReport([]string{"--jsonl", jsonlPath, "--min-score", "50"})
	})
	if !strings.Contains(stdout, "No findings above the filter threshold") {
		t.Fatalf("expected empty-findings message, got:\n%s", stdout)
	}
}

func TestPeelSubcommand(t *testing.T) {
	cases := []struct {
		in      []string
		cmd     string
		leftLen int
	}{
		{[]string{"--urls", "x"}, "", 2},
		{[]string{"scan", "--urls", "x"}, "scan", 2},
		{[]string{"replay", "--seq", "0"}, "replay", 2},
		{[]string{"report", "--format", "json"}, "report", 2},
		{[]string{"help"}, "help", 0},
		{[]string{}, "", 0},
		{[]string{"-h"}, "", 1},
	}
	for _, c := range cases {
		got, rest := peelSubcommand(c.in)
		if got != c.cmd {
			t.Fatalf("peelSubcommand(%v) cmd = %q want %q", c.in, got, c.cmd)
		}
		if len(rest) != c.leftLen {
			t.Fatalf("peelSubcommand(%v) rest len = %d want %d", c.in, len(rest), c.leftLen)
		}
	}
}

// captureStdout redirects os.Stdout for the duration of f and returns what
// was written. Falls back to the caller's stdout on pipe failures.
func captureStdout(t *testing.T, f func() error) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	runErr := f()
	w.Close()
	<-done
	os.Stdout = orig
	if runErr != nil {
		t.Fatalf("f() returned error: %v\noutput:\n%s", runErr, buf.String())
	}
	return buf.String()
}
