package input

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeURLsFile(t *testing.T, content string) string {
	t.Helper()
	return writeTempFile(t, "urls.txt", content)
}

func TestURLsRejectsBadSchemes(t *testing.T) {
	cases := []string{
		"ftp://example.com/foo",
		"file:///etc/passwd",
		"javascript:alert(1)",
		"gopher://example.com",
		"data:text/plain;base64,QUFB",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			path := writeURLsFile(t, raw+"\n")
			if _, err := LoadURLs(path); err == nil {
				t.Fatalf("expected scheme %q to be rejected", raw)
			}
		})
	}
}

func TestURLsRejectsControlChars(t *testing.T) {
	cases := map[string]string{
		"NUL": "https://example.com/a\x00b",
		"CR":  "https://example.com/a\rb",
		"LF":  "https://example.com/a\nb",
		"TAB": "https://example.com/a\tb",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeURLsFile(t, raw+"\n")
			if _, err := LoadURLs(path); err == nil {
				t.Fatalf("expected %s URL to be rejected", name)
			}
		})
	}
}

func TestURLsRejectsMissingHost(t *testing.T) {
	path := writeURLsFile(t, "https:///path\n")
	if _, err := LoadURLs(path); err == nil {
		t.Fatal("expected host-less URL to be rejected")
	}
}

func TestURLsRejectsFragments(t *testing.T) {
	path := writeURLsFile(t, "https://example.com/a#frag\n")
	if _, err := LoadURLs(path); err == nil {
		t.Fatal("expected fragment URL to be rejected")
	}
}

func TestURLsRejectsUserinfo(t *testing.T) {
	path := writeURLsFile(t, "https://user:pass@example.com/\n")
	if _, err := LoadURLs(path); err == nil {
		t.Fatal("expected userinfo URL to be rejected")
	}
}

func TestURLsRejectsEmptyFile(t *testing.T) {
	path := writeURLsFile(t, "")
	if _, err := LoadURLs(path); err == nil {
		t.Fatal("expected empty file to be rejected")
	}

	commentsOnly := writeURLsFile(t, "# nothing\n\n# still nothing\n")
	if _, err := LoadURLs(commentsOnly); err == nil {
		t.Fatal("expected comments-only file to be rejected")
	}
}

func TestURLsRejectsOversizedLine(t *testing.T) {
	long := "https://example.com/" + strings.Repeat("a", 32*1024)
	path := writeURLsFile(t, long+"\n")
	if _, err := LoadURLs(path); err == nil {
		t.Fatal("expected oversized line to be rejected")
	}
}

func TestURLsRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.txt")
	var buf bytes.Buffer
	line := "https://example.com/path\n"
	for buf.Len() < maxURLFileBytes+4*1024 {
		buf.WriteString(line)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatalf("write big file: %v", err)
	}
	if _, err := LoadURLs(path); err == nil {
		t.Fatal("expected oversized file to be rejected")
	}
}

func TestURLsAcceptsIPv6Bracketed(t *testing.T) {
	path := writeURLsFile(t, "http://[::1]:8080/path\n")
	urls, err := LoadURLs(path)
	if err != nil {
		t.Fatalf("ipv6 url rejected: %v", err)
	}
	if len(urls) != 1 {
		t.Fatalf("expected 1 url, got %d", len(urls))
	}
}
