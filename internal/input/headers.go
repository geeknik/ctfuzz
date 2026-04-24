package input

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

const (
	maxHeaderLineBytes = 16 * 1024
	maxHeaderFileBytes = 1024 * 1024
)

func LoadHeaders(path string) (http.Header, error) {
	headers := http.Header{}
	if strings.TrimSpace(path) == "" {
		return headers, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxHeaderFileBytes {
		return nil, fmt.Errorf("headers file exceeds %d bytes", maxHeaderFileBytes)
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024), maxHeaderLineBytes)
	seen := map[string]struct{}{}

	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("headers line %d: expected Name: value", lineNo)
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if err := validateHeaderName(name); err != nil {
			return nil, fmt.Errorf("headers line %d: %w", lineNo, err)
		}
		if err := validateHeaderValue(value); err != nil {
			return nil, fmt.Errorf("headers line %d: %w", lineNo, err)
		}
		canonical := http.CanonicalHeaderKey(name)
		lower := strings.ToLower(canonical)
		if _, exists := seen[lower]; exists {
			return nil, fmt.Errorf("headers line %d: duplicate header %q", lineNo, canonical)
		}
		seen[lower] = struct{}{}
		headers.Set(canonical, value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return headers, nil
}

func validateHeaderName(name string) error {
	if name == "" {
		return errors.New("header name must not be empty")
	}
	for _, r := range name {
		if r > 127 || !isTokenChar(byte(r)) {
			return fmt.Errorf("invalid header name %q", name)
		}
	}

	switch strings.ToLower(name) {
	case "content-type":
		return errors.New("Content-Type is controlled by ctfuzz")
	case "content-length", "transfer-encoding", "trailer", "connection", "host":
		return fmt.Errorf("%s is managed by the HTTP client", http.CanonicalHeaderKey(name))
	default:
		return nil
	}
}

func validateHeaderValue(value string) error {
	if len(value) > 8192 {
		return errors.New("header value exceeds 8192 bytes")
	}
	for _, r := range value {
		if r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return errors.New("header value contains a control character")
		}
	}
	return nil
}

func isTokenChar(c byte) bool {
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}
