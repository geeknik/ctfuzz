package render

import (
	"encoding/json"
	"mime/multipart"
	"net/url"
	"strings"
	"testing"
)

func TestJSONRendererEmitsValidJSON(t *testing.T) {
	body, err := JSON(map[string]any{"id": json.Number("1"), "name": "ctfuzz"})
	if err != nil {
		t.Fatalf("JSON returned error: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("rendered body is not valid JSON: %v", err)
	}
	if decoded["name"] != "ctfuzz" {
		t.Fatalf("unexpected decoded payload: %#v", decoded)
	}
}

func TestXMLRendererEscapesSpecialCharacters(t *testing.T) {
	body, err := XML(map[string]any{
		"name": "a < b & c",
		"user": map[string]any{"id": json.Number("1")},
	}, "root")
	if err != nil {
		t.Fatalf("XML returned error: %v", err)
	}

	got := string(body)
	if !strings.Contains(got, "<name>a &lt; b &amp; c</name>") {
		t.Fatalf("expected escaped XML value, got %s", got)
	}
	if !strings.Contains(got, "<user><id>1</id></user>") {
		t.Fatalf("expected nested XML value, got %s", got)
	}
}

func TestFormRendererFlattensNestedObjects(t *testing.T) {
	body, err := Form(map[string]any{
		"user": map[string]any{"name": "alice"},
		"z":    true,
	})
	if err != nil {
		t.Fatalf("Form returned error: %v", err)
	}
	if got, want := string(body), "user.name=alice&z=true"; got != want {
		t.Fatalf("form mismatch: got %q want %q", got, want)
	}
}

func TestAllRegisteredContentTypesRender(t *testing.T) {
	payload := map[string]any{
		"id":   json.Number("1"),
		"name": "ctfuzz",
		"user": map[string]any{"role": "user"},
	}
	for _, ct := range AllContentTypes {
		body, err := Body(ct, payload)
		if err != nil {
			t.Fatalf("Body(%q): %v", ct, err)
		}
		if len(body) == 0 {
			t.Fatalf("Body(%q) returned an empty body", ct)
		}
	}
}

func TestResolveTypesSupportsGroupsExactTypesAndDedupes(t *testing.T) {
	types, err := ResolveTypes("core,json-family,application/scim+json,application/json")
	if err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}
	if len(types) <= len(CoreContentTypes) {
		t.Fatalf("expected expanded type set, got %#v", types)
	}

	seen := map[string]struct{}{}
	for _, ct := range types {
		if _, ok := seen[ct]; ok {
			t.Fatalf("duplicate content type %q in %#v", ct, types)
		}
		seen[ct] = struct{}{}
	}
	if _, ok := seen["application/scim+json"]; !ok {
		t.Fatalf("exact +json type was not preserved: %#v", types)
	}
}

func TestExactJSONSuffixRendersAsJSON(t *testing.T) {
	body, err := Body("application/scim+json", map[string]any{"id": "1"})
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("+json body was not valid JSON: %v", err)
	}
	if decoded["id"] != "1" {
		t.Fatalf("decoded mismatch: %#v", decoded)
	}
}

func TestNDJSONRendererTerminatesWithNewline(t *testing.T) {
	body, err := Body(ContentTypeNDJSON, map[string]any{"id": "1"})
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	if !strings.HasSuffix(string(body), "\n") {
		t.Fatalf("expected newline-terminated NDJSON, got %q", body)
	}
}

func TestMultipartRendererIsParseable(t *testing.T) {
	body, err := Body(ContentTypeMultipart, map[string]any{
		"id":   "1",
		"user": map[string]any{"name": "alice"},
	})
	if err != nil {
		t.Fatalf("Body: %v", err)
	}

	reader := multipart.NewReader(strings.NewReader(string(body)), multipartBoundary)
	form, err := reader.ReadForm(1024 * 1024)
	if err != nil {
		t.Fatalf("multipart body was not parseable: %v", err)
	}
	defer form.RemoveAll()

	values := url.Values(form.Value)
	if got := values.Get("id"); got != "1" {
		t.Fatalf("id mismatch: %q", got)
	}
	if got := values.Get("user.name"); got != "alice" {
		t.Fatalf("nested value mismatch: %q", got)
	}
}

func TestYAMLRendererQuotesStringsAndSortsKeys(t *testing.T) {
	body, err := Body(ContentTypeYAML, map[string]any{
		"z": "a:b # not comment",
		"a": json.Number("1"),
	})
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	if got, want := string(body), "a: 1\nz: \"a:b # not comment\"\n"; got != want {
		t.Fatalf("YAML mismatch:\ngot  %q\nwant %q", got, want)
	}
}

func TestFormUTF8KeepsURLValuesSemantics(t *testing.T) {
	body, err := Body(ContentTypeFormUTF8, map[string]any{"q": "a b&c"})
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatalf("parse form body: %v", err)
	}
	if got := values.Get("q"); got != "a b&c" {
		t.Fatalf("form value mismatch: %q", got)
	}
}
