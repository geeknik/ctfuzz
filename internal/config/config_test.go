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

func TestParseTypesSupportsExactSuffixType(t *testing.T) {
	types, err := parseTypes("application/scim+json")
	if err != nil {
		t.Fatalf("parseTypes: %v", err)
	}
	if len(types) != 1 || types[0] != "application/scim+json" {
		t.Fatalf("unexpected types: %#v", types)
	}
}
