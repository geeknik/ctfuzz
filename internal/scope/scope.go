// Package scope parses host allowlists for bounty-program scope
// enforcement. A Matcher is a simple exact-or-wildcard-subdomain set
// with no regex, no negation, and no CIDR — the aim is auditable,
// predictable behavior, not expressiveness.
package scope

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

const (
	maxScopeFileBytes = 1024 * 1024
	maxScopeLineBytes = 2048
)

type Matcher struct {
	exact    map[string]struct{}
	suffixes []string
}

func (m *Matcher) Empty() bool {
	if m == nil {
		return true
	}
	return len(m.exact) == 0 && len(m.suffixes) == 0
}

// Load parses a scope file. Each non-blank, non-comment line is either:
//   - an exact host ("example.com")
//   - a subdomain wildcard ("*.example.com") which matches any strict
//     subdomain but NOT the bare registrable domain
//
// Host comparison is lowercase and port-insensitive.
func Load(path string) (*Matcher, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxScopeFileBytes {
		return nil, fmt.Errorf("scope file exceeds %d bytes", maxScopeFileBytes)
	}

	m := &Matcher{exact: map[string]struct{}{}}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024), maxScopeLineBytes)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := m.addPattern(line); err != nil {
			return nil, fmt.Errorf("scope line %d: %w", lineNo, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if m.Empty() {
		return nil, errors.New("scope file contained no patterns")
	}
	return m, nil
}

func (m *Matcher) addPattern(raw string) error {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if lower == "" {
		return errors.New("empty pattern")
	}
	if strings.HasPrefix(lower, "*.") {
		base := lower[2:]
		if !validHost(base) {
			return fmt.Errorf("invalid wildcard pattern %q", raw)
		}
		suffix := "." + base
		m.suffixes = append(m.suffixes, suffix)
		return nil
	}
	if strings.ContainsAny(lower, "*?/ \t") {
		return fmt.Errorf("unsupported pattern %q", raw)
	}
	if !validHost(lower) {
		return fmt.Errorf("invalid hostname %q", raw)
	}
	m.exact[lower] = struct{}{}
	return nil
}

func validHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-', r == '.', r == ':':
			// colons allow IPv6 literals after u.Hostname() strips brackets
		default:
			return false
		}
	}
	return true
}

// AllowsURL reports whether the URL's host falls within the scope.
// A nil matcher allows everything.
func (m *Matcher) AllowsURL(rawURL string) bool {
	if m == nil {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	return m.AllowsHost(u.Hostname())
}

func (m *Matcher) AllowsHost(host string) bool {
	if m == nil {
		return true
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if _, ok := m.exact[host]; ok {
		return true
	}
	for _, suffix := range m.suffixes {
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return true
		}
	}
	return false
}
