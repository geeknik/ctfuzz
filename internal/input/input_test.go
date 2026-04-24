package input

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadURLsIgnoresCommentsBlanksAndDeduplicates(t *testing.T) {
	path := writeTempFile(t, "urls.txt", `
# comment
https://example.com/api

https://example.com/api
http://localhost:8080/path?x=1
`)

	urls, err := LoadURLs(path)
	if err != nil {
		t.Fatalf("LoadURLs returned error: %v", err)
	}
	if len(urls) != 2 {
		t.Fatalf("expected 2 urls, got %d: %#v", len(urls), urls)
	}
}

func TestLoadURLsRejectsUserinfo(t *testing.T) {
	path := writeTempFile(t, "urls.txt", "https://user:pass@example.com/api\n")

	if _, err := LoadURLs(path); err == nil {
		t.Fatal("expected userinfo URL to be rejected")
	}
}

func TestLoadHeadersRejectsContentType(t *testing.T) {
	path := writeTempFile(t, "headers.txt", "Content-Type: application/json\n")

	if _, err := LoadHeaders(path); err == nil {
		t.Fatal("expected Content-Type header to be rejected")
	}
}

func TestLoadHeadersRejectsDuplicateHeader(t *testing.T) {
	path := writeTempFile(t, "headers.txt", "X-Test: one\nx-test: two\n")

	if _, err := LoadHeaders(path); err == nil {
		t.Fatal("expected duplicate header to be rejected")
	}
}

func TestLoadHeadersParsesStaticHeaders(t *testing.T) {
	path := writeTempFile(t, "headers.txt", "Authorization: Bearer token\nUser-Agent: custom\n")

	headers, err := LoadHeaders(path)
	if err != nil {
		t.Fatalf("LoadHeaders returned error: %v", err)
	}
	if got := headers.Get("Authorization"); got != "Bearer token" {
		t.Fatalf("Authorization mismatch: %q", got)
	}
	if got := headers.Get("User-Agent"); got != "custom" {
		t.Fatalf("User-Agent mismatch: %q", got)
	}
	if headers.Get(http.CanonicalHeaderKey("authorization")) == "" {
		t.Fatal("expected canonical header lookup to work")
	}
}

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}
