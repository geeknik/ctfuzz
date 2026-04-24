package analyze

import (
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"

	"ctfuzz/internal/render"
	"ctfuzz/internal/result"
)

type signal struct {
	score      int
	reason     string
	reportable bool
}

func Summarize(targetURL string, requests []result.Request) result.Summary {
	statuses := make(map[string]int, len(requests))
	for _, req := range requests {
		statuses[variantKey(req)] = req.Status
	}

	signals := collect(requests)

	score := 0
	reasons := make([]string, 0, len(signals))
	for _, s := range signals {
		score += s.score
		reasons = append(reasons, s.reason)
	}
	if score > 100 {
		score = 100
	}
	reason := "no differential signal detected"
	if len(reasons) > 0 {
		reason = strings.Join(reasons, "; ")
	}

	summary := result.Summary{
		URL:         targetURL,
		Kind:        "summary",
		Interesting: score > 0 && hasReportableSignal(signals),
		Score:       score,
		Reason:      reason,
		Statuses:    statuses,
	}
	if groups, ok := headerHashStructural(requests); ok {
		summary.HeaderGroups = groups
	}
	return summary
}

// SummaryKey identifies a per-(URL, method) summary bucket. Kept here so
// main.go and tests don't have to rebuild the key format.
func SummaryKey(url, method string) string {
	return method + " " + url
}

func MarkInteresting(requests []result.Request, summaries map[string]result.Summary) {
	for i := range requests {
		key := SummaryKey(requests[i].URL, requests[i].Method)
		requests[i].Interesting = summaries[key].Interesting
	}
}

func ConsoleStatus(summary result.Summary) string {
	keys := make([]string, 0, len(summary.Statuses))
	for key := range summary.Statuses {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	if len(keys) > 6 {
		byStatus := map[int][]string{}
		for _, key := range keys {
			status := summary.Statuses[key]
			byStatus[status] = append(byStatus[status], render.ShortName(key))
		}
		statuses := make([]int, 0, len(byStatus))
		for status := range byStatus {
			statuses = append(statuses, status)
		}
		sort.Ints(statuses)

		parts := make([]string, 0, len(statuses))
		for _, status := range statuses {
			names := byStatus[status]
			sort.Strings(names)
			parts = append(parts, fmt.Sprintf("%d=%s", status, compactNames(names)))
		}
		return strings.Join(parts, " ")
	}

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", render.ShortName(key), summary.Statuses[key]))
	}
	return strings.Join(parts, " ")
}

func compactNames(names []string) string {
	if len(names) <= 4 {
		return strings.Join(names, ",")
	}
	return strings.Join(names[:4], ",") + fmt.Sprintf(",+%d", len(names)-4)
}

func collect(requests []result.Request) []signal {
	var out []signal

	switch {
	case hasAuthBypassShape(requests):
		out = append(out, signal{score: 40, reason: "success status differs from authorization failure", reportable: true})
	case hasSuccessAndFailure(requests):
		out = append(out, signal{score: 30, reason: "success status differs from error status", reportable: true})
	}

	if oneContentTypeHas5xx(requests) {
		out = append(out, signal{score: 25, reason: "5xx response occurs for only one content type", reportable: true})
	}
	if parserSignalDifferential(requests) {
		out = append(out, signal{score: 15, reason: "parser or framework keyword reflected by only some content types", reportable: true})
	}
	if oneContentTypeReflectsCanary(requests) {
		out = append(out, signal{score: 20, reason: "canary reflected by only one content type", reportable: true})
	}

	switch {
	case redirectHostDiffers(requests):
		out = append(out, signal{score: 15, reason: "redirect points to a different host for at least one content type", reportable: true})
	case redirectDiffers(requests):
		out = append(out, signal{score: 10, reason: "redirect location differs", reportable: true})
	}

	reportMetadata := !uniformErrorStatus(requests)
	if materiallyDifferentSize(requests) {
		out = append(out, signal{score: 10, reason: "response size differs by more than 50%", reportable: reportMetadata && responseSizeOutlier(requests)})
	}
	if bodyHashDifferential(requests) {
		out = append(out, signal{score: 10, reason: "response body hash differs across content types", reportable: reportMetadata && bodyHashOutlier(requests)})
	}
	switch {
	case headerHashStructuralFires(requests):
		out = append(out, signal{
			score:      25,
			reason:     "response headers cluster by content-type family",
			reportable: true,
		})
	case headerFingerprintDifferential(requests):
		out = append(out, signal{score: 5, reason: "response header fingerprint differs across content types"})
	}
	if durationDiffers(requests) {
		out = append(out, signal{score: 5, reason: "response time differs by more than 3x"})
	}
	return out
}

// variantKey returns the string used to uniquely identify a request variant
// inside a per-(URL, method) cluster. For matching Content-Type requests this
// is the Content-Type header; for mismatch variants it is the scenario name
// (e.g., "json-as-xml") so two variants sharing a header don't collide.
func variantKey(req result.Request) string {
	if req.VariantName != "" {
		return req.VariantName
	}
	if req.ContentType != "" {
		return req.ContentType
	}
	return "(no-content-type)"
}

func hasReportableSignal(signals []signal) bool {
	for _, s := range signals {
		if s.reportable {
			return true
		}
	}
	return false
}

func hasSuccessAndFailure(requests []result.Request) bool {
	hasSuccess := false
	hasFailure := false
	for _, req := range requests {
		if req.Status >= 200 && req.Status < 300 {
			hasSuccess = true
		}
		if req.Status >= 400 && req.Status < 600 {
			hasFailure = true
		}
	}
	return hasSuccess && hasFailure
}

func hasAuthBypassShape(requests []result.Request) bool {
	hasAuthFailure := false
	hasSuccess := false
	for _, req := range requests {
		if req.Status == 401 || req.Status == 403 {
			hasAuthFailure = true
		}
		if req.Status == 200 || req.Status == 204 || req.Status == 302 {
			hasSuccess = true
		}
	}
	return hasAuthFailure && hasSuccess
}

func oneContentTypeHas5xx(requests []result.Request) bool {
	count := 0
	for _, req := range requests {
		if req.Status >= 500 && req.Status < 600 {
			count++
		}
	}
	return count == 1
}

func oneContentTypeReflectsCanary(requests []result.Request) bool {
	count := 0
	for _, req := range requests {
		if req.CanaryReflected {
			count++
		}
	}
	return count == 1 && len(requests) > 1
}

func materiallyDifferentSize(requests []result.Request) bool {
	if len(requests) < 2 {
		return false
	}
	minLen := int64(math.MaxInt64)
	maxLen := int64(0)
	for _, req := range requests {
		if req.Error != "" {
			continue
		}
		if req.ResponseLen < minLen {
			minLen = req.ResponseLen
		}
		if req.ResponseLen > maxLen {
			maxLen = req.ResponseLen
		}
	}
	if minLen == int64(math.MaxInt64) {
		return false
	}
	if minLen == 0 {
		return maxLen > 0
	}
	return maxLen > minLen+(minLen/2)
}

func redirectDiffers(requests []result.Request) bool {
	seen := map[string]struct{}{}
	for _, req := range requests {
		if req.Error != "" || !isRedirectStatus(req.Status) {
			continue
		}
		seen[req.RedirectLocation] = struct{}{}
	}
	return len(seen) > 1
}

func redirectHostDiffers(requests []result.Request) bool {
	hosts := map[string]struct{}{}
	hasRedirect := false
	for _, req := range requests {
		if req.Error != "" || !isRedirectStatus(req.Status) {
			continue
		}
		if req.RedirectLocation == "" {
			hosts[""] = struct{}{}
			continue
		}
		hasRedirect = true
		if u, err := url.Parse(req.RedirectLocation); err == nil {
			hosts[strings.ToLower(u.Host)] = struct{}{}
		} else {
			hosts[req.RedirectLocation] = struct{}{}
		}
	}
	return hasRedirect && len(hosts) >= 2
}

func isRedirectStatus(status int) bool {
	return status >= 300 && status < 400
}

func uniformErrorStatus(requests []result.Request) bool {
	status := 0
	observed := false
	for _, req := range requests {
		if req.Error != "" || req.Status == 0 {
			continue
		}
		if !observed {
			status = req.Status
			observed = true
			continue
		}
		if req.Status != status {
			return false
		}
	}
	return observed && status >= 400
}

func parserSignalDifferential(requests []result.Request) bool {
	observed := 0
	hits := 0
	for _, req := range requests {
		if req.Error != "" {
			continue
		}
		observed++
		if req.ErrorKeyword {
			hits++
		}
	}
	return hits > 0 && hits < observed
}

func bodyHashDifferential(requests []result.Request) bool {
	hashes := map[string]struct{}{}
	for _, req := range requests {
		if req.Error != "" || req.BodySHA256 == "" {
			continue
		}
		hashes[req.BodySHA256] = struct{}{}
	}
	return len(hashes) >= 2
}

func bodyHashOutlier(requests []result.Request) bool {
	counts := map[string]int{}
	for _, req := range requests {
		if req.Error != "" || req.BodySHA256 == "" {
			continue
		}
		counts[req.BodySHA256]++
	}
	return hasMinorityOutlier(counts)
}

func responseSizeOutlier(requests []result.Request) bool {
	counts := map[int64]int{}
	for _, req := range requests {
		if req.Error != "" {
			continue
		}
		counts[req.ResponseLen]++
	}
	return hasMinorityOutlier(counts)
}

func headerFingerprintDifferential(requests []result.Request) bool {
	hashes := map[string]struct{}{}
	for _, req := range requests {
		if req.Error != "" || req.HeaderSHA256 == "" {
			continue
		}
		hashes[req.HeaderSHA256] = struct{}{}
	}
	return len(hashes) >= 2
}

func hasMinorityOutlier[T comparable](counts map[T]int) bool {
	if len(counts) < 2 {
		return false
	}
	hasMajority := false
	hasSingle := false
	for _, count := range counts {
		if count >= 2 {
			hasMajority = true
		}
		if count == 1 {
			hasSingle = true
		}
	}
	return hasMajority && hasSingle
}

// headerHashStructural returns the per-group breakdown of response headers
// when the header hashes cluster into a small number of groups with at least
// one group of size ≥ 2. This is the signal that distinguishes "Google-shape"
// routing by content-type family (clean 2-group split) from "Microsoft-shape"
// per-request jitter (many near-singleton groups).
//
// Threshold: num_groups ≤ max(2, observed/4). Small N stays lenient so a
// 3-way run with 2 groups can still fire; large N demands tight clustering.
func headerHashStructural(requests []result.Request) ([]result.HeaderGroup, bool) {
	groups := map[string][]result.Request{}
	observed := 0
	for _, req := range requests {
		if req.Error != "" || req.HeaderSHA256 == "" {
			continue
		}
		groups[req.HeaderSHA256] = append(groups[req.HeaderSHA256], req)
		observed++
	}
	if len(groups) < 2 {
		return nil, false
	}
	threshold := observed / 4
	if threshold < 2 {
		threshold = 2
	}
	if len(groups) > threshold {
		return nil, false
	}
	maxSize := 0
	for _, members := range groups {
		if len(members) > maxSize {
			maxSize = len(members)
		}
	}
	if maxSize < 2 {
		return nil, false
	}
	return buildHeaderGroups(groups), true
}

func headerHashStructuralFires(requests []result.Request) bool {
	_, ok := headerHashStructural(requests)
	return ok
}

func buildHeaderGroups(groups map[string][]result.Request) []result.HeaderGroup {
	hashes := make([]string, 0, len(groups))
	for h := range groups {
		hashes = append(hashes, h)
	}
	sort.Slice(hashes, func(i, j int) bool {
		si, sj := len(groups[hashes[i]]), len(groups[hashes[j]])
		if si != sj {
			return si > sj
		}
		return hashes[i] < hashes[j]
	})

	differing := computeDifferingHeaders(groups, hashes)
	out := make([]result.HeaderGroup, 0, len(hashes))
	for _, h := range hashes {
		members := groups[h]
		cts := make([]string, 0, len(members))
		for _, m := range members {
			cts = append(cts, m.ContentType)
		}
		sort.Strings(cts)

		var headers map[string]string
		if len(differing) > 0 {
			headers = map[string]string{}
			rep := members[0].ResponseHeaders
			for name := range differing {
				headers[name] = rep[name]
			}
		}

		short := h
		if len(short) > 12 {
			short = short[:12]
		}
		out = append(out, result.HeaderGroup{
			Hash:         short,
			ContentTypes: cts,
			Headers:      headers,
		})
	}
	return out
}

// computeDifferingHeaders returns the whitelisted header names whose value
// (including absence, represented as the empty string) differs between at
// least two groups. Since each group has identical request byte headers
// by construction, sampling the first member of each group is sufficient.
func computeDifferingHeaders(groups map[string][]result.Request, hashes []string) map[string]struct{} {
	names := map[string]struct{}{}
	for _, h := range hashes {
		members := groups[h]
		if len(members) == 0 {
			continue
		}
		for name := range members[0].ResponseHeaders {
			names[name] = struct{}{}
		}
	}
	diff := map[string]struct{}{}
	for name := range names {
		seen := map[string]struct{}{}
		for _, h := range hashes {
			members := groups[h]
			if len(members) == 0 {
				continue
			}
			seen[members[0].ResponseHeaders[name]] = struct{}{}
			if len(seen) > 1 {
				break
			}
		}
		if len(seen) > 1 {
			diff[name] = struct{}{}
		}
	}
	return diff
}

func durationDiffers(requests []result.Request) bool {
	if len(requests) < 2 {
		return false
	}
	minDuration := int64(math.MaxInt64)
	maxDuration := int64(0)
	for _, req := range requests {
		if req.Error != "" || req.DurationMS <= 0 {
			continue
		}
		if req.DurationMS < minDuration {
			minDuration = req.DurationMS
		}
		if req.DurationMS > maxDuration {
			maxDuration = req.DurationMS
		}
	}
	if minDuration == int64(math.MaxInt64) || minDuration == 0 {
		return false
	}
	return maxDuration > minDuration*3
}
