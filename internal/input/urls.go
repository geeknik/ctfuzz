package input

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

const (
	maxURLLineBytes = 16 * 1024
	maxURLFileBytes = 10 * 1024 * 1024
)

func LoadURLs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxURLFileBytes {
		return nil, fmt.Errorf("URL file exceeds %d bytes", maxURLFileBytes)
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024), maxURLLineBytes)

	var urls []string
	seen := map[string]struct{}{}
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		clean, err := validateURL(line)
		if err != nil {
			return nil, fmt.Errorf("urls line %d: %w", lineNo, err)
		}
		if _, exists := seen[clean]; exists {
			continue
		}
		seen[clean] = struct{}{}
		urls = append(urls, clean)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(urls) == 0 {
		return nil, errors.New("URL file did not contain any targets")
	}
	return urls, nil
}

func validateURL(raw string) (string, error) {
	if strings.ContainsAny(raw, "\r\n\t\x00") {
		return "", errors.New("URL contains a control character")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("URL is not parseable")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("URL scheme must be http or https")
	}
	if u.Host == "" {
		return "", errors.New("URL must include a host")
	}
	if u.User != nil {
		return "", errors.New("URL must not include userinfo")
	}
	if u.Fragment != "" {
		return "", errors.New("URL fragments are not supported")
	}
	return u.String(), nil
}
