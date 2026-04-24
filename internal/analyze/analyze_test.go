package analyze

import (
	"fmt"
	"strings"
	"testing"

	"ctfuzz/internal/render"
	"ctfuzz/internal/result"
)

func TestSummarizeDetectsAuthBypassShape(t *testing.T) {
	summary := Summarize("https://example.com/api", []result.Request{
		{ContentType: render.ContentTypeJSON, Status: 403, ResponseLen: 20},
		{ContentType: render.ContentTypeXML, Status: 403, ResponseLen: 20},
		{ContentType: render.ContentTypeForm, Status: 200, ResponseLen: 200},
	})

	if !summary.Interesting {
		t.Fatal("expected summary to be interesting")
	}
	if summary.Score < 40 {
		t.Fatalf("expected auth signal score, got %d", summary.Score)
	}
	if got := summary.Statuses[render.ContentTypeForm]; got != 200 {
		t.Fatalf("form status mismatch: %d", got)
	}
}

func TestSummarizeIgnoresSameResponses(t *testing.T) {
	summary := Summarize("https://example.com/same", []result.Request{
		{ContentType: render.ContentTypeJSON, Status: 200, ResponseLen: 10},
		{ContentType: render.ContentTypeXML, Status: 200, ResponseLen: 10},
		{ContentType: render.ContentTypeForm, Status: 200, ResponseLen: 10},
	})

	if summary.Interesting {
		t.Fatalf("expected same responses to be uninteresting: %#v", summary)
	}
}

func TestParserSignalNotFiredWhenAllResponsesMatch(t *testing.T) {
	summary := Summarize("https://example.com/error", []result.Request{
		{ContentType: render.ContentTypeJSON, Status: 500, ErrorKeyword: true, ResponseLen: 100, BodySHA256: "abc"},
		{ContentType: render.ContentTypeXML, Status: 500, ErrorKeyword: true, ResponseLen: 100, BodySHA256: "abc"},
		{ContentType: render.ContentTypeForm, Status: 500, ErrorKeyword: true, ResponseLen: 100, BodySHA256: "abc"},
	})
	if summary.Interesting {
		t.Fatalf("expected uniform error with keywords to be uninteresting: %#v", summary)
	}
}

func TestParserSignalFiresWhenDifferential(t *testing.T) {
	summary := Summarize("https://example.com/partial-error", []result.Request{
		{ContentType: render.ContentTypeJSON, Status: 200, ErrorKeyword: false, ResponseLen: 50, BodySHA256: "a"},
		{ContentType: render.ContentTypeXML, Status: 500, ErrorKeyword: true, ResponseLen: 60, BodySHA256: "b"},
		{ContentType: render.ContentTypeForm, Status: 200, ErrorKeyword: false, ResponseLen: 50, BodySHA256: "a"},
	})
	if !summary.Interesting {
		t.Fatalf("expected differential parser signal to mark interesting")
	}
}

func TestBodyHashDifferentialSignal(t *testing.T) {
	summary := Summarize("https://example.com/hashes", []result.Request{
		{ContentType: render.ContentTypeJSON, Status: 200, ResponseLen: 10, BodySHA256: "h1"},
		{ContentType: render.ContentTypeXML, Status: 200, ResponseLen: 10, BodySHA256: "h1"},
		{ContentType: render.ContentTypeForm, Status: 200, ResponseLen: 10, BodySHA256: "h2"},
	})
	if !summary.Interesting {
		t.Fatalf("expected body hash outlier to mark interesting")
	}
}

func TestAllUniqueBodyHashesAreDiagnosticButNotInteresting(t *testing.T) {
	summary := Summarize("https://example.com/raw-echo", []result.Request{
		{ContentType: render.ContentTypeJSON, Status: 200, ResponseLen: 10, BodySHA256: "h1"},
		{ContentType: render.ContentTypeXML, Status: 200, ResponseLen: 20, BodySHA256: "h2"},
		{ContentType: render.ContentTypeForm, Status: 200, ResponseLen: 30, BodySHA256: "h3"},
	})
	if summary.Interesting {
		t.Fatalf("expected all-unique fingerprint differences to remain diagnostic only: %#v", summary)
	}
	if summary.Score == 0 {
		t.Fatalf("expected diagnostic score to be preserved")
	}
}

func TestFingerprintOnlyUniformErrorIsNotInteresting(t *testing.T) {
	summary := Summarize("https://example.com/forbidden", []result.Request{
		{ContentType: render.ContentTypeJSON, Status: 403, ResponseLen: 100, BodySHA256: "h1", HeaderSHA256: "hh1"},
		{ContentType: render.ContentTypeXML, Status: 403, ResponseLen: 100, BodySHA256: "h2", HeaderSHA256: "hh2"},
		{ContentType: render.ContentTypeForm, Status: 403, ResponseLen: 100, BodySHA256: "h3", HeaderSHA256: "hh3"},
	})
	if summary.Interesting {
		t.Fatalf("expected uniform error fingerprint noise to be uninteresting: %#v", summary)
	}
	if summary.Score != 15 {
		t.Fatalf("expected weak diagnostic score to be preserved, got %d", summary.Score)
	}
}

func TestHeaderFingerprintOnlyIsNotInteresting(t *testing.T) {
	summary := Summarize("https://example.com/headers", []result.Request{
		{ContentType: render.ContentTypeJSON, Status: 200, ResponseLen: 10, BodySHA256: "same", HeaderSHA256: "hh1"},
		{ContentType: render.ContentTypeXML, Status: 200, ResponseLen: 10, BodySHA256: "same", HeaderSHA256: "hh2"},
		{ContentType: render.ContentTypeForm, Status: 200, ResponseLen: 10, BodySHA256: "same", HeaderSHA256: "hh3"},
	})
	if summary.Interesting {
		t.Fatalf("expected header-only fingerprint noise to be uninteresting: %#v", summary)
	}
	if summary.Score != 5 {
		t.Fatalf("expected weak header score to be preserved, got %d", summary.Score)
	}
}

func TestRedirectHostDifferentialSignal(t *testing.T) {
	summary := Summarize("https://example.com/redir", []result.Request{
		{ContentType: render.ContentTypeJSON, Status: 302, RedirectLocation: "https://same.example.com/ok", ResponseLen: 0},
		{ContentType: render.ContentTypeXML, Status: 302, RedirectLocation: "https://attacker.test/steal", ResponseLen: 0},
		{ContentType: render.ContentTypeForm, Status: 302, RedirectLocation: "https://same.example.com/ok", ResponseLen: 0},
	})
	if !summary.Interesting {
		t.Fatalf("expected redirect host difference to mark interesting")
	}
	if !strings.Contains(summary.Reason, "different host") {
		t.Fatalf("expected host-diff reason, got %q", summary.Reason)
	}
}

func TestLocationHeaderOnNonRedirectStatusIsNotRedirectSignal(t *testing.T) {
	summary := Summarize("https://example.com/error-location", []result.Request{
		{ContentType: render.ContentTypeJSON, Status: 403, RedirectLocation: "https://same.example.com/ok", ResponseLen: 0},
		{ContentType: render.ContentTypeXML, Status: 403, RedirectLocation: "https://other.example.com/nope", ResponseLen: 0},
		{ContentType: render.ContentTypeForm, Status: 403, RedirectLocation: "", ResponseLen: 0},
	})
	if summary.Interesting {
		t.Fatalf("expected non-redirect Location headers to be uninteresting: %#v", summary)
	}
	if strings.Contains(summary.Reason, "redirect") {
		t.Fatalf("did not expect redirect reason for non-redirect statuses: %q", summary.Reason)
	}
}

func TestHeaderHashStructural_GoogleShape(t *testing.T) {
	jsonFamily := []string{
		render.ContentTypeJSON,
		render.ContentTypeHALJSON,
		render.ContentTypeLDJSON,
		render.ContentTypeVendorJSON,
		render.ContentTypePatchJSON,
		render.ContentTypeMergeJSON,
		render.ContentTypeProblemJSON,
		render.ContentTypeSCIMJSON,
	}
	others := []string{
		render.ContentTypeXML,
		render.ContentTypeTextXML,
		render.ContentTypeForm,
		render.ContentTypeMultipart,
		render.ContentTypeYAML,
		render.ContentTypePlain,
		render.ContentTypeOctetStream,
	}

	reqs := make([]result.Request, 0, len(jsonFamily)+len(others))
	for _, ct := range jsonFamily {
		reqs = append(reqs, result.Request{
			ContentType:  ct,
			Status:       405,
			ResponseLen:  1589,
			BodySHA256:   "body-A",
			HeaderSHA256: "hash-json-family",
			ResponseHeaders: map[string]string{
				"Vary":            "Accept",
				"X-Frame-Options": "DENY",
				"Server":          "gws",
			},
		})
	}
	for _, ct := range others {
		reqs = append(reqs, result.Request{
			ContentType:  ct,
			Status:       405,
			ResponseLen:  1589,
			BodySHA256:   "body-A",
			HeaderSHA256: "hash-other",
			ResponseHeaders: map[string]string{
				"Vary":   "Accept, Accept-Encoding",
				"Server": "gws",
			},
		})
	}

	summary := Summarize("https://example.test/clustered", reqs)
	if !summary.Interesting {
		t.Fatalf("expected structural cluster to be interesting: score=%d reason=%q", summary.Score, summary.Reason)
	}
	if summary.Score < 25 {
		t.Fatalf("expected score ≥25 from structural signal, got %d", summary.Score)
	}
	if !strings.Contains(summary.Reason, "cluster") {
		t.Fatalf("expected cluster reason, got %q", summary.Reason)
	}
	if len(summary.HeaderGroups) != 2 {
		t.Fatalf("expected 2 header groups, got %d", len(summary.HeaderGroups))
	}
	// Larger group (others: 7) should be listed before JSON family (8 is larger, then wait).
	// jsonFamily has 8 members, others has 7. jsonFamily should lead.
	if len(summary.HeaderGroups[0].ContentTypes) != len(jsonFamily) {
		t.Fatalf("expected largest group first, got sizes %d/%d",
			len(summary.HeaderGroups[0].ContentTypes), len(summary.HeaderGroups[1].ContentTypes))
	}
	diffKeys := summary.HeaderGroups[0].Headers
	if _, ok := diffKeys["Vary"]; !ok {
		t.Fatalf("expected Vary in differing headers, got %#v", diffKeys)
	}
	if _, ok := diffKeys["X-Frame-Options"]; !ok {
		t.Fatalf("expected X-Frame-Options in differing headers, got %#v", diffKeys)
	}
	if _, ok := diffKeys["Server"]; ok {
		t.Fatalf("Server should NOT be in differing headers (same across groups): %#v", diffKeys)
	}
	// Absent header in the "others" group must be recorded as empty string.
	if v, ok := summary.HeaderGroups[1].Headers["X-Frame-Options"]; !ok || v != "" {
		t.Fatalf("expected absent header to surface as empty string, got %q ok=%v", v, ok)
	}
}

func TestHeaderHashStructural_MicrosoftShape(t *testing.T) {
	// 14 distinct header hashes across 35 requests: {1,1,1,1,1,2,2,3,3,3,4,4,4,5}.
	sizes := []int{1, 1, 1, 1, 1, 2, 2, 3, 3, 3, 4, 4, 4, 5}
	ct := 0
	reqs := []result.Request{}
	for gi, size := range sizes {
		for i := 0; i < size; i++ {
			reqs = append(reqs, result.Request{
				ContentType:  fmt.Sprintf("application/ct%d", ct),
				Status:       403,
				ResponseLen:  4410,
				BodySHA256:   fmt.Sprintf("body-%d", ct),
				HeaderSHA256: fmt.Sprintf("hash-%d", gi),
			})
			ct++
		}
	}
	summary := Summarize("https://example.test/jitter", reqs)
	if summary.Interesting {
		t.Fatalf("expected jittery header noise to stay uninteresting: score=%d reason=%q",
			summary.Score, summary.Reason)
	}
	if len(summary.HeaderGroups) != 0 {
		t.Fatalf("expected no header groups for jittery noise, got %d", len(summary.HeaderGroups))
	}
}

func TestHeaderHashStructural_AllUnique(t *testing.T) {
	reqs := []result.Request{}
	for i := 0; i < 8; i++ {
		reqs = append(reqs, result.Request{
			ContentType:  fmt.Sprintf("application/ct%d", i),
			Status:       200,
			ResponseLen:  10,
			BodySHA256:   "b",
			HeaderSHA256: fmt.Sprintf("hash-%d", i),
		})
	}
	summary := Summarize("https://example.test/unique", reqs)
	if summary.Interesting {
		t.Fatalf("expected 8-unique-hash case to be uninteresting")
	}
	if len(summary.HeaderGroups) != 0 {
		t.Fatalf("expected no header groups, got %d", len(summary.HeaderGroups))
	}
}

func TestHeaderHashStructural_Uniform(t *testing.T) {
	reqs := []result.Request{}
	for i := 0; i < 8; i++ {
		reqs = append(reqs, result.Request{
			ContentType:  fmt.Sprintf("application/ct%d", i),
			Status:       200,
			ResponseLen:  10,
			BodySHA256:   "b",
			HeaderSHA256: "one",
		})
	}
	summary := Summarize("https://example.test/same", reqs)
	if len(summary.HeaderGroups) != 0 {
		t.Fatalf("expected no header groups when headers are uniform, got %d", len(summary.HeaderGroups))
	}
}

func TestHeaderHashStructural_SmallNPermissive(t *testing.T) {
	// 3 requests, 2 groups (sizes 2 + 1). Size 1 ≤ threshold = max(2, 3/4=0) = 2. Fires.
	reqs := []result.Request{
		{ContentType: render.ContentTypeJSON, Status: 200, ResponseLen: 10, BodySHA256: "b", HeaderSHA256: "g1",
			ResponseHeaders: map[string]string{"Server": "nginx"}},
		{ContentType: render.ContentTypeXML, Status: 200, ResponseLen: 10, BodySHA256: "b", HeaderSHA256: "g1",
			ResponseHeaders: map[string]string{"Server": "nginx"}},
		{ContentType: render.ContentTypeForm, Status: 200, ResponseLen: 10, BodySHA256: "b", HeaderSHA256: "g2",
			ResponseHeaders: map[string]string{"Server": "gunicorn"}},
	}
	summary := Summarize("https://example.test/small", reqs)
	if !summary.Interesting {
		t.Fatalf("expected small-N 2-group clustering to be interesting: %#v", summary)
	}
	if len(summary.HeaderGroups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(summary.HeaderGroups))
	}
	if v, ok := summary.HeaderGroups[0].Headers["Server"]; !ok || v != "nginx" {
		t.Fatalf("expected nginx in larger group, got %q", v)
	}
}

func TestScoreCappedAt100(t *testing.T) {
	// Stack every signal at once.
	summary := Summarize("https://example.com/many", []result.Request{
		{ContentType: render.ContentTypeJSON, Status: 403, ResponseLen: 5, BodySHA256: "a", HeaderSHA256: "ha", DurationMS: 10, CanaryReflected: false, ErrorKeyword: false},
		{ContentType: render.ContentTypeXML, Status: 500, ResponseLen: 200, BodySHA256: "b", HeaderSHA256: "hb", DurationMS: 200, CanaryReflected: true, ErrorKeyword: true, RedirectLocation: "https://attacker.test/x"},
		{ContentType: render.ContentTypeForm, Status: 200, ResponseLen: 500, BodySHA256: "c", HeaderSHA256: "hc", DurationMS: 50, CanaryReflected: false, ErrorKeyword: false, RedirectLocation: "https://same.example.com/ok"},
	})
	if summary.Score > 100 {
		t.Fatalf("score should cap at 100, got %d", summary.Score)
	}
	if summary.Score < 80 {
		t.Fatalf("expected stacked signals to push score high, got %d", summary.Score)
	}
}

func TestConsoleStatusCompactsBroadMatrices(t *testing.T) {
	summary := result.Summary{
		Statuses: map[string]int{
			render.ContentTypeJSON:        200,
			render.ContentTypeJSONUTF8:    200,
			render.ContentTypeVendorJSON:  200,
			render.ContentTypeMergeJSON:   200,
			render.ContentTypeProblemJSON: 200,
			render.ContentTypeXML:         415,
			render.ContentTypeForm:        415,
		},
	}
	got := ConsoleStatus(summary)
	if !strings.Contains(got, "200=") || !strings.Contains(got, "+1") || !strings.Contains(got, "415=form,xml") {
		t.Fatalf("unexpected compact status: %q", got)
	}
}
