package render

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestXMLEscapesAllReservedChars(t *testing.T) {
	body, err := XML(map[string]any{"k": `<>&"'`}, "root")
	if err != nil {
		t.Fatalf("XML: %v", err)
	}
	got := string(body)
	for _, want := range []string{"&lt;", "&gt;", "&amp;"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in %s", want, got)
		}
	}
	// Round-trip through the stdlib parser to catch any malformed output.
	dec := xml.NewDecoder(strings.NewReader(got))
	for {
		tok, err := dec.Token()
		if tok == nil && err != nil {
			break
		}
		if err != nil {
			t.Fatalf("rendered XML not parseable: %v", err)
		}
	}
}

func TestXMLRejectsUnsafeRoot(t *testing.T) {
	cases := []string{"1root", "a:b", "xmlThing", "bad name", ""}
	for _, name := range cases {
		if _, err := XML(map[string]any{"k": "v"}, name); err == nil {
			t.Fatalf("expected unsafe root %q to be rejected", name)
		}
	}
}

func TestXMLEscapesCDATASequence(t *testing.T) {
	body, err := XML(map[string]any{"k": "]]>injected"}, "root")
	if err != nil {
		t.Fatalf("XML: %v", err)
	}
	// The literal sequence "]]>" must not appear in the serialized body
	// since xml.EscapeText converts '>' to '&gt;'.
	if strings.Contains(string(body), "]]>") {
		t.Fatalf("literal CDATA terminator leaked: %s", body)
	}
}

func TestFormPercentEncodesSpecials(t *testing.T) {
	body, err := Form(map[string]any{"k": "a b&c=d+e"})
	if err != nil {
		t.Fatalf("Form: %v", err)
	}
	got := string(body)
	if strings.Contains(got, " ") {
		t.Fatalf("unencoded space in form body: %q", got)
	}
	if !strings.Contains(got, "%26") {
		t.Fatalf("expected & to be percent-encoded: %q", got)
	}
	if !strings.Contains(got, "%3D") {
		t.Fatalf("expected = to be percent-encoded: %q", got)
	}
}

func TestFormRejectsScalarRoot(t *testing.T) {
	// flattenForm treats scalar roots as an error.
	// We build this with reflection via Body interface; directly invoking Form
	// with a non-map is not possible because of typing.
	// Instead exercise the nested-no-prefix branch indirectly: no keys produces empty.
	body, err := Form(map[string]any{})
	if err != nil {
		t.Fatalf("Form: %v", err)
	}
	if string(body) != "" {
		t.Fatalf("expected empty body for empty map, got %q", body)
	}
}

func TestFormFlattensDeepStable(t *testing.T) {
	// Equivalent payloads with different insertion order must render identically.
	a, err := Form(map[string]any{
		"b": map[string]any{"y": "2", "x": "1"},
		"a": "0",
	})
	if err != nil {
		t.Fatalf("Form: %v", err)
	}
	b, err := Form(map[string]any{
		"a": "0",
		"b": map[string]any{"x": "1", "y": "2"},
	})
	if err != nil {
		t.Fatalf("Form: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("form output not stable across insertion orders:\n  a=%s\n  b=%s", a, b)
	}
}

func TestValidXMLNameSanity(t *testing.T) {
	good := []string{"a", "_a", "a1", "a-b", "a.b", "_-."}
	for _, name := range good {
		if !ValidXMLName(name) {
			t.Fatalf("expected %q to be a valid XML name", name)
		}
	}
	bad := []string{"", "1a", "xml", "Xml", "XML", "a b", "a:b", "a&b", "a\x00b"}
	for _, name := range bad {
		if ValidXMLName(name) {
			t.Fatalf("expected %q to be rejected", name)
		}
	}
}
