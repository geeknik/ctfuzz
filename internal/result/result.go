package result

type Request struct {
	Seq              int               `json:"seq"`
	URL              string            `json:"url"`
	Method           string            `json:"method"`
	ContentType      string            `json:"content_type"`
	BodyEncoding     string            `json:"body_encoding,omitempty"`
	VariantName      string            `json:"variant,omitempty"`
	Status           int               `json:"status"`
	DurationMS       int64             `json:"duration_ms"`
	ResponseLen      int64             `json:"response_len"`
	BodySHA256       string            `json:"body_sha256"`
	HeaderSHA256     string            `json:"header_sha256"`
	RedirectLocation string            `json:"redirect_location"`
	CanaryReflected  bool              `json:"canary_reflected"`
	ErrorKeyword     bool              `json:"error_keyword"`
	BodyTruncated    bool              `json:"body_truncated"`
	Interesting      bool              `json:"interesting"`
	Error            string            `json:"error"`
	Body             string            `json:"body,omitempty"`
	ResponseHeaders  map[string]string `json:"response_headers,omitempty"`
}

// Manifest is the first line of every scan JSONL. It carries the metadata
// needed to reproduce the run (canary, methods, variants) so downstream
// tooling like `ctfuzz replay` and `ctfuzz report` don't need to rebuild
// state from inference.
type Manifest struct {
	Kind     string   `json:"kind"`
	Schema   int      `json:"schema"`
	Created  string   `json:"created"`
	Canary   string   `json:"canary,omitempty"`
	Methods  []string `json:"methods"`
	Types    []string `json:"types"`
	Mismatch bool     `json:"mismatch,omitempty"`
}

type Summary struct {
	URL          string         `json:"url"`
	Method       string         `json:"method,omitempty"`
	Kind         string         `json:"kind"`
	Interesting  bool           `json:"interesting"`
	Score        int            `json:"score"`
	Reason       string         `json:"reason"`
	Statuses     map[string]int `json:"statuses"`
	HeaderGroups []HeaderGroup  `json:"header_groups,omitempty"`
}

// HeaderGroup describes a cluster of content types whose response headers
// share a single fingerprint. Headers contains only the response-header
// values that actually differ across groups — values shared by every group
// are omitted. An empty string means the header was absent in this group.
type HeaderGroup struct {
	Hash         string            `json:"hash"`
	ContentTypes []string          `json:"content_types"`
	Headers      map[string]string `json:"headers,omitempty"`
}
