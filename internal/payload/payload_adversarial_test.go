package payload

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePayloadFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return path
}

func TestLoadRejectsNonObjectRoots(t *testing.T) {
	cases := map[string]string{
		"string": `"just a string"`,
		"number": `42`,
		"null":   `null`,
		"bool":   `true`,
		"array":  `[1,2,3]`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := writePayloadFile(t, "p.json", body)
			if _, err := Load(path, 1024, ""); err == nil {
				t.Fatalf("expected %s root to be rejected", name)
			}
		})
	}
}

func TestLoadRejectsEmptyObject(t *testing.T) {
	path := writePayloadFile(t, "p.json", `{}`)
	if _, err := Load(path, 1024, ""); err == nil {
		t.Fatal("expected empty object payload to be rejected")
	}
}

func TestLoadRejectsTrailingGarbage(t *testing.T) {
	path := writePayloadFile(t, "p.json", `{"a":"b"} { "c": "d" }`)
	if _, err := Load(path, 1024, ""); err == nil {
		t.Fatal("expected trailing JSON value to be rejected")
	}
}

func TestLoadRejectsTrailingNonWhitespace(t *testing.T) {
	path := writePayloadFile(t, "p.json", `{"a":"b"}garbage`)
	if _, err := Load(path, 1024, ""); err == nil {
		t.Fatal("expected trailing garbage to be rejected")
	}
}

func TestLoadAcceptsTrailingWhitespace(t *testing.T) {
	path := writePayloadFile(t, "p.json", `{"a":"b"}   `+"\n\n\t ")
	if _, err := Load(path, 1024, ""); err != nil {
		t.Fatalf("trailing whitespace unexpectedly rejected: %v", err)
	}
}

func TestLoadRejectsBOMPrefix(t *testing.T) {
	body := "\xef\xbb\xbf" + `{"a":"b"}`
	path := writePayloadFile(t, "p.json", body)
	if _, err := Load(path, 1024, ""); err == nil {
		t.Fatal("expected BOM-prefixed JSON to be rejected")
	}
}

func TestLoadRejectsOversizedFile(t *testing.T) {
	path := writePayloadFile(t, "p.json", `{"a":"`+strings.Repeat("x", 2000)+`"}`)
	if _, err := Load(path, 1024, ""); err == nil {
		t.Fatal("expected oversized payload file to be rejected")
	}
}

func TestLoadRejectsDeeplyNested(t *testing.T) {
	var buf bytes.Buffer
	depth := 64
	for i := 0; i < depth; i++ {
		buf.WriteString(`{"a":`)
	}
	buf.WriteString(`"leaf"`)
	for i := 0; i < depth; i++ {
		buf.WriteByte('}')
	}
	path := writePayloadFile(t, "p.json", buf.String())
	if _, err := Load(path, 1024*1024, ""); err == nil {
		t.Fatal("expected deeply nested payload to be rejected")
	}
}

func TestLoadRejectsBadKeys(t *testing.T) {
	cases := map[string]string{
		"empty-key":      `{"":"v"}`,
		"digit-start":    `{"9bad":"v"}`,
		"xml-reserved":   `{"xmlfoo":"v"}`,
		"xml-reserved-2": `{"XMLThing":"v"}`,
		"colon":          `{"a:b":"v"}`,
		"cr":             "{\"a\rb\":\"v\"}",
		"lf":             "{\"a\nb\":\"v\"}",
		"nul":            "{\"a\x00b\":\"v\"}",
		"too-long":       `{"` + strings.Repeat("a", 129) + `":"v"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := writePayloadFile(t, "p.json", body)
			if _, err := Load(path, 1024*1024, ""); err == nil {
				t.Fatalf("expected %s key to be rejected", name)
			}
		})
	}
}

func TestLoadRejectsControlCharsInStringValues(t *testing.T) {
	cases := map[string]string{
		"nul":  "{\"a\":\"x\x00y\"}",
		"bell": "{\"a\":\"x\x07y\"}",
		"vt":   "{\"a\":\"x\x0by\"}",
		"del":  "{\"a\":\"x\x7fy\"}",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := writePayloadFile(t, "p.json", body)
			if _, err := Load(path, 1024, ""); err == nil {
				t.Fatalf("expected %s control char in value to be rejected", name)
			}
		})
	}
}

func TestLoadAcceptsNewlineTabsInValues(t *testing.T) {
	path := writePayloadFile(t, "p.json", `{"a":"line1\nline2\ttab"}`)
	got, err := Load(path, 1024, "")
	if err != nil {
		t.Fatalf("valid whitespace rejected: %v", err)
	}
	if got["a"] != "line1\nline2\ttab" {
		t.Fatalf("value mismatch: %#v", got["a"])
	}
}

func TestLoadRejectsNaNInfNumbers(t *testing.T) {
	cases := []string{`{"a":NaN}`, `{"a":Infinity}`, `{"a":-Infinity}`}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			path := writePayloadFile(t, "p.json", body)
			if _, err := Load(path, 1024, ""); err == nil {
				t.Fatalf("expected %q to be rejected", body)
			}
		})
	}
}

func TestLoadDuplicateKeysLastWriteWins(t *testing.T) {
	path := writePayloadFile(t, "p.json", `{"a":"first","a":"second"}`)
	got, err := Load(path, 1024, "")
	if err != nil {
		t.Fatalf("duplicate keys unexpectedly rejected: %v", err)
	}
	if got["a"] != "second" {
		t.Fatalf("expected last-write-wins, got %#v", got["a"])
	}
}

func TestLoadRejectsNestedArrays(t *testing.T) {
	cases := []string{
		`{"a":[1,2]}`,
		`{"a":{"b":[1,2]}}`,
		`{"a":{"b":{"c":[1]}}}`,
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			path := writePayloadFile(t, "p.json", body)
			if _, err := Load(path, 1024, ""); err == nil {
				t.Fatalf("expected array in %q to be rejected", body)
			}
		})
	}
}

func TestLoadCanaryOverwriteProtection(t *testing.T) {
	path := writePayloadFile(t, "p.json", `{"a":"b","_ctfuzz_canary":"preset"}`)
	got, err := Load(path, 1024, "other")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got["_ctfuzz_canary"] != "preset" {
		t.Fatalf("expected existing canary preserved, got %#v", got["_ctfuzz_canary"])
	}
}

func TestLoadRejectsLargeStringValue(t *testing.T) {
	big := strings.Repeat("a", maxStringValue+10)
	body := `{"k":"` + big + `"}`
	path := writePayloadFile(t, "p.json", body)
	if _, err := Load(path, int64(len(body))+16, ""); err == nil {
		t.Fatal("expected oversized string value to be rejected")
	}
}

func TestLoadFileDoesNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	if _, err := Load(path, 1024, ""); err == nil {
		t.Fatal("expected missing file to be rejected")
	}
}
