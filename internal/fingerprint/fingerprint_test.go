package fingerprint

import (
	"net/http"
	"testing"
)

func TestSHA256Stable(t *testing.T) {
	a := SHA256([]byte("ctfuzz"))
	b := SHA256([]byte("ctfuzz"))
	if a == "" || a != b {
		t.Fatalf("hash should be stable: %q %q", a, b)
	}
}

func TestHeaderSHA256StableAcrossMapOrder(t *testing.T) {
	h1 := http.Header{}
	h1.Set("X-B", "2")
	h1.Set("X-A", "1")

	h2 := http.Header{}
	h2.Set("X-A", "1")
	h2.Set("X-B", "2")

	if got, want := HeaderSHA256(h1), HeaderSHA256(h2); got != want {
		t.Fatalf("header hash mismatch: got %q want %q", got, want)
	}
}

func TestContainsErrorKeyword(t *testing.T) {
	if !ContainsErrorKeyword([]byte("XML parser returned a parse error")) {
		t.Fatal("expected parser keyword to be detected")
	}
}
