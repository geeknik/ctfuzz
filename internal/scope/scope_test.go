package scope

import (
	"os"
	"path/filepath"
	"testing"
)

func writeScope(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestExactMatch(t *testing.T) {
	m, err := Load(writeScope(t, "example.com\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !m.AllowsHost("example.com") {
		t.Fatal("expected exact match")
	}
	if m.AllowsHost("foo.example.com") {
		t.Fatal("exact pattern must not match subdomain")
	}
	if m.AllowsHost("evil-example.com") {
		t.Fatal("substring must not match")
	}
}

func TestWildcardSubdomainOnly(t *testing.T) {
	m, err := Load(writeScope(t, "*.example.com\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !m.AllowsHost("foo.example.com") {
		t.Fatal("expected subdomain match")
	}
	if !m.AllowsHost("a.b.example.com") {
		t.Fatal("expected deep subdomain match")
	}
	if m.AllowsHost("example.com") {
		t.Fatal("wildcard must not match the bare registrable domain")
	}
	if m.AllowsHost("evil.example.com.attacker.com") {
		t.Fatal("suffix collision must not match")
	}
}

func TestPortStrippedFromHost(t *testing.T) {
	m, err := Load(writeScope(t, "example.com\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !m.AllowsURL("https://example.com:8443/path") {
		t.Fatal("port should be stripped before comparison")
	}
	if !m.AllowsURL("http://EXAMPLE.com/") {
		t.Fatal("case should be normalized")
	}
}

func TestCommentsAndBlanks(t *testing.T) {
	m, err := Load(writeScope(t, "# comment\n\n  # indented comment\nexample.com\n\n*.api.example.com\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !m.AllowsHost("example.com") || !m.AllowsHost("v1.api.example.com") {
		t.Fatal("expected both patterns to load")
	}
}

func TestRejectsInvalidPatterns(t *testing.T) {
	cases := map[string]string{
		"regex":       "[a-z]+.com",
		"negation":    "!example.com",
		"path":        "example.com/admin",
		"space":       "example .com",
		"bare-wild":   "*.",
		"wild-suffix": "foo.*.com",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeScope(t, body+"\n")); err == nil {
				t.Fatalf("expected %s pattern to be rejected", name)
			}
		})
	}
}

func TestRejectsEmptyScopeFile(t *testing.T) {
	if _, err := Load(writeScope(t, "# nothing here\n\n")); err == nil {
		t.Fatal("expected empty scope to be rejected")
	}
}

func TestNilMatcherAllowsEverything(t *testing.T) {
	var m *Matcher
	if !m.AllowsURL("https://anything.example.com/x") {
		t.Fatal("nil matcher should allow any URL")
	}
}

func TestEmptyHostRejected(t *testing.T) {
	m, err := Load(writeScope(t, "example.com\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if m.AllowsURL("not-a-url") {
		t.Fatal("non-URL must not be allowed")
	}
	if m.AllowsHost("") {
		t.Fatal("empty host must not be allowed")
	}
}

func TestIPv6Literal(t *testing.T) {
	m, err := Load(writeScope(t, "::1\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !m.AllowsURL("http://[::1]:8080/path") {
		t.Fatal("expected IPv6 literal match")
	}
}
