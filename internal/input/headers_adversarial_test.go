package input

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeHeadersFile(t *testing.T, content string) string {
	t.Helper()
	return writeTempFile(t, "headers.txt", content)
}

func TestHeadersRejectsCRLFSmuggling(t *testing.T) {
	cases := map[string]string{
		"CR-in-value":  "X-Test: a\rb\n",
		"LF-in-value":  "X-Test: a\nb\n",
		"NUL-in-value": "X-Test: a\x00b\n",
		"DEL-in-value": "X-Test: a\x7fb\n",
		"VT-in-value":  "X-Test: a\x0bb\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeHeadersFile(t, body)
			if _, err := LoadHeaders(path); err == nil {
				t.Fatalf("expected %s to be rejected", name)
			}
		})
	}
}

func TestHeadersRejectsInvalidNames(t *testing.T) {
	cases := map[string]string{
		"empty":     ": value\n",
		"space":     "X Bad: value\n",
		"non-ascii": "X-Té: value\n",
		"control":   "X-\x01: value\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeHeadersFile(t, body)
			if _, err := LoadHeaders(path); err == nil {
				t.Fatalf("expected %s header name to be rejected", name)
			}
		})
	}
}

func TestHeadersRejectsHopByHopAndFramingHeaders(t *testing.T) {
	cases := []string{
		"Content-Length: 0",
		"Transfer-Encoding: chunked",
		"Trailer: X-Test",
		"Connection: close",
		"Host: example.com",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			path := writeHeadersFile(t, raw+"\n")
			if _, err := LoadHeaders(path); err == nil {
				t.Fatalf("expected %q to be rejected", raw)
			}
		})
	}
}

func TestHeadersRejectsOversizedValue(t *testing.T) {
	big := "X-Pad: " + strings.Repeat("A", 8193) + "\n"
	path := writeHeadersFile(t, big)
	if _, err := LoadHeaders(path); err == nil {
		t.Fatal("expected oversized value to be rejected")
	}
}

func TestHeadersRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.txt")
	var buf bytes.Buffer
	for i := 0; buf.Len() < maxHeaderFileBytes+1024; i++ {
		buf.WriteString("X-Dup-")
		buf.WriteString(strings.Repeat("a", 16))
		buf.WriteString(": value\n")
	}
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatalf("write big file: %v", err)
	}
	if _, err := LoadHeaders(path); err == nil {
		t.Fatal("expected oversized file to be rejected")
	}
}

func TestHeadersRejectsMissingColon(t *testing.T) {
	path := writeHeadersFile(t, "X-NoColon just a value\n")
	if _, err := LoadHeaders(path); err == nil {
		t.Fatal("expected missing-colon line to be rejected")
	}
}

func TestHeadersAcceptsTabInValue(t *testing.T) {
	path := writeHeadersFile(t, "X-Test: a\tb\n")
	headers, err := LoadHeaders(path)
	if err != nil {
		t.Fatalf("tab in value unexpectedly rejected: %v", err)
	}
	if got := headers.Get("X-Test"); got != "a\tb" {
		t.Fatalf("tab value mismatch: %q", got)
	}
}

func TestHeadersSkipsCommentsAndBlanks(t *testing.T) {
	path := writeHeadersFile(t, "# a comment\n\nX-Test: v\n# another\n")
	headers, err := LoadHeaders(path)
	if err != nil {
		t.Fatalf("LoadHeaders: %v", err)
	}
	if got := headers.Get("X-Test"); got != "v" {
		t.Fatalf("header mismatch: %q", got)
	}
}

func TestHeadersRejectsContentTypeCaseInsensitive(t *testing.T) {
	path := writeHeadersFile(t, "content-TYPE: text/plain\n")
	if _, err := LoadHeaders(path); err == nil {
		t.Fatal("expected case-insensitive Content-Type to be rejected")
	}
}
