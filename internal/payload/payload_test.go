package payload

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsArraysInV1Payload(t *testing.T) {
	path := tempPayload(t, `{"ids":[1,2,3]}`)

	if _, err := Load(path, 1024, ""); err == nil {
		t.Fatal("expected array payload to be rejected")
	}
}

func TestLoadInjectsCanaryWithoutOverwriting(t *testing.T) {
	path := tempPayload(t, `{"name":"alice"}`)

	got, err := Load(path, 1024, "ctfuzz_test")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got["_ctfuzz_canary"] != "ctfuzz_test" {
		t.Fatalf("canary not injected: %#v", got)
	}
}

func TestLoadRejectsUnsafeXMLKey(t *testing.T) {
	path := tempPayload(t, `{"1bad":"value"}`)

	if _, err := Load(path, 1024, ""); err == nil {
		t.Fatal("expected unsafe XML key to be rejected")
	}
}

func tempPayload(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "payload.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	return path
}
