package config

import (
	"testing"

	"ctfuzz/internal/render"
)

func TestParseTypesAllIsBroadSpectrum(t *testing.T) {
	types, err := parseTypes("all")
	if err != nil {
		t.Fatalf("parseTypes: %v", err)
	}
	if len(types) <= len(render.CoreContentTypes) {
		t.Fatalf("expected all to expand beyond core types, got %#v", types)
	}
}

func TestParseTypesCorePreservesOriginalTrio(t *testing.T) {
	types, err := parseTypes("core")
	if err != nil {
		t.Fatalf("parseTypes: %v", err)
	}
	if len(types) != len(render.CoreContentTypes) {
		t.Fatalf("core length mismatch: %#v", types)
	}
	for i := range types {
		if types[i] != render.CoreContentTypes[i] {
			t.Fatalf("core[%d] mismatch: got %q want %q", i, types[i], render.CoreContentTypes[i])
		}
	}
}

func TestParseMethodsDefaultFromSingular(t *testing.T) {
	got, err := parseMethods("", "post")
	if err != nil {
		t.Fatalf("parseMethods: %v", err)
	}
	if len(got) != 1 || got[0] != "POST" {
		t.Fatalf("expected [POST], got %v", got)
	}
}

func TestParseMethodsCommaListDeduplicated(t *testing.T) {
	got, err := parseMethods("POST, put ,PATCH,post", "POST")
	if err != nil {
		t.Fatalf("parseMethods: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 deduped methods, got %v", got)
	}
	want := []string{"POST", "PUT", "PATCH"}
	for i, m := range want {
		if got[i] != m {
			t.Fatalf("pos %d: got %q want %q", i, got[i], m)
		}
	}
}

func TestParseMethodsRejectsBogus(t *testing.T) {
	cases := []string{"PROPFIND", "", "FOO,BAR", "POST, ,PUT"}
	for _, raw := range cases {
		if _, err := parseMethods(raw, "POST"); err == nil && raw != "" {
			t.Fatalf("expected %q to be rejected", raw)
		}
	}
}

func TestParseTypesSupportsExactSuffixType(t *testing.T) {
	types, err := parseTypes("application/scim+json")
	if err != nil {
		t.Fatalf("parseTypes: %v", err)
	}
	if len(types) != 1 || types[0] != "application/scim+json" {
		t.Fatalf("unexpected types: %#v", types)
	}
}
