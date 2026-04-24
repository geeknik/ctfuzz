package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
)

var ErrorKeywords = []string{
	"stack trace",
	"stacktrace",
	"traceback",
	"exception",
	"uncaughtexception",
	"unhandledexception",
	"parse error",
	"unexpected token",
	"invalid character",
	"invalid syntax",
	"syntaxerror",
	"xml parser",
	"saxparseexception",
	"org.xml.sax",
	"jsonparseexception",
	"json.decoder",
	"nullpointerexception",
	"typeerror",
	"valueerror",
	"runtime error",
	"panic",
	"fatal error",
	"php fatal",
	"undefined index",
	"yaml.scanner",
	"yaml.parser",
	"com.fasterxml",
	"deserializ",
	"marshalerror",
}

func SHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func HeaderSHA256(headers http.Header) string {
	var names []string
	for name := range headers {
		names = append(names, strings.ToLower(name))
	}
	sort.Strings(names)

	var b strings.Builder
	for _, lowerName := range names {
		canonical := http.CanonicalHeaderKey(lowerName)
		values := append([]string(nil), headers.Values(canonical)...)
		sort.Strings(values)
		b.WriteString(lowerName)
		b.WriteByte(':')
		for _, value := range values {
			b.WriteString(value)
			b.WriteByte('\x00')
		}
		b.WriteByte('\n')
	}
	return SHA256([]byte(b.String()))
}

// triageHeaderNames is the whitelist of response headers we retain per request
// for cross-content-type diffing. It intentionally omits per-request noise
// (Date, Request-ID, etc.) and sensitive cookie values; Set-Cookie is handled
// separately below, returning names only.
var triageHeaderNames = []string{
	// Server/framework fingerprint
	"Server",
	"X-Powered-By",
	"X-AspNet-Version",
	"X-AspNetMvc-Version",
	"Via",
	"X-Served-By",
	"X-Cache",
	"X-Cache-Hits",

	// Routing/negotiation
	"Vary",
	"Allow",
	"Accept-Patch",
	"Accept-Ranges",
	"Link",
	"Content-Type",
	"Content-Language",
	"Content-Encoding",
	"Content-Length",

	// Cache/freshness (commonly varies by handler/family)
	"Cache-Control",
	"Alt-Svc",
	"ETag",
	"Age",
	"Expires",
	"Last-Modified",
	"Pragma",

	// Security headers
	"Content-Security-Policy",
	"Content-Security-Policy-Report-Only",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"X-XSS-Protection",
	"X-UA-Compatible",
	"X-Robots-Tag",
	"Strict-Transport-Security",
	"Referrer-Policy",
	"Permissions-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Resource-Policy",
	"Cross-Origin-Embedder-Policy",
	"X-Download-Options",
	"P3P",
	"Reporting-Endpoints",
	"Report-To",
	"NEL",
	"Origin-Agent-Cluster",
	"Clear-Site-Data",

	// CORS
	"Access-Control-Allow-Origin",
	"Access-Control-Allow-Methods",
	"Access-Control-Allow-Headers",
	"Access-Control-Allow-Credentials",
	"Access-Control-Expose-Headers",
	"Access-Control-Max-Age",
	"Timing-Allow-Origin",

	// Auth challenge
	"WWW-Authenticate",
	"Proxy-Authenticate",

	// Rate-limit / retry signals
	"Retry-After",
	"X-RateLimit-Limit",
	"X-RateLimit-Remaining",
	"X-RateLimit-Reset",
	"X-RateLimit-Used",
	"RateLimit-Limit",
	"RateLimit-Remaining",
	"RateLimit-Reset",

	// Observability (often leaks route/handler identity)
	"Server-Timing",
}

const maxTriageHeaderValue = 1024

// ExtractTriageHeaders returns a map of safe-to-log response headers for use
// by the analyzer. Values are capped at maxTriageHeaderValue bytes. Set-Cookie
// is flattened to a comma-separated list of cookie names under the synthetic
// key "Set-Cookie-Names" — names only, no values, no attributes.
func ExtractTriageHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, name := range triageHeaderNames {
		values := h.Values(name)
		if len(values) == 0 {
			continue
		}
		joined := strings.Join(values, ", ")
		if len(joined) > maxTriageHeaderValue {
			joined = joined[:maxTriageHeaderValue]
		}
		out[name] = joined
	}
	if names := cookieNames(h.Values("Set-Cookie")); len(names) > 0 {
		out["Set-Cookie-Names"] = strings.Join(names, ",")
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cookieNames(lines []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func ContainsErrorKeyword(body []byte) bool {
	lower := strings.ToLower(string(body))
	for _, keyword := range ErrorKeywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}
