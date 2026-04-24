package payload

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"ctfuzz/internal/render"
)

const (
	canaryKey       = "_ctfuzz_canary"
	maxPayloadDepth = 32
	maxStringValue  = 64 * 1024
)

func Load(path string, maxBytes int64, canary string) (map[string]any, error) {
	data, err := readLimitedFile(path, maxBytes)
	if err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("payload must be valid JSON: %w", err)
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("payload must contain exactly one JSON value")
	}

	obj, ok := root.(map[string]any)
	if !ok {
		return nil, errors.New("payload root must be a JSON object")
	}
	if err := validateValue("$", obj, 0); err != nil {
		return nil, err
	}
	if canary != "" {
		if _, exists := obj[canaryKey]; !exists {
			obj[canaryKey] = canary
		}
	}
	return obj, nil
}

func readLimitedFile(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("payload file exceeds %d bytes", maxBytes)
	}
	return data, nil
}

func validateValue(path string, value any, depth int) error {
	if depth > maxPayloadDepth {
		return fmt.Errorf("%s: payload nesting exceeds %d levels", path, maxPayloadDepth)
	}
	switch v := value.(type) {
	case map[string]any:
		if len(v) == 0 && path == "$" {
			return errors.New("payload object must contain at least one key")
		}
		for key, child := range v {
			if err := validateKey(path, key); err != nil {
				return err
			}
			next := path + "." + key
			if err := validateValue(next, child, depth+1); err != nil {
				return err
			}
		}
	case []any:
		return fmt.Errorf("%s: arrays are not supported in v1 payloads", path)
	case string:
		if len(v) > maxStringValue {
			return fmt.Errorf("%s: string value exceeds %d bytes", path, maxStringValue)
		}
		if !utf8.ValidString(v) {
			return fmt.Errorf("%s: string value is not valid UTF-8", path)
		}
		for _, r := range v {
			if r == '\t' || r == '\n' || r == '\r' {
				continue
			}
			if r < 0x20 || r == 0x7f {
				return fmt.Errorf("%s: string value contains a control character", path)
			}
		}
	case json.Number:
		if len(v.String()) > 128 {
			return fmt.Errorf("%s: numeric value is too long", path)
		}
		if _, err := v.Int64(); err == nil {
			return nil
		}
		if _, err := v.Float64(); err != nil {
			return fmt.Errorf("%s: invalid JSON number", path)
		}
	case bool, nil:
		return nil
	default:
		return fmt.Errorf("%s: unsupported JSON value type %T", path, value)
	}
	return nil
}

func validateKey(path, key string) error {
	if key == "" {
		return fmt.Errorf("%s: object keys must not be empty", path)
	}
	if len(key) > 128 {
		return fmt.Errorf("%s.%s: object key exceeds 128 bytes", path, key)
	}
	if strings.ContainsAny(key, "\r\n\t\x00") {
		return fmt.Errorf("%s.%s: object key contains a control character", path, key)
	}
	if !render.ValidXMLName(key) {
		return fmt.Errorf("%s.%s: object key is not a safe XML element name", path, key)
	}
	return nil
}
