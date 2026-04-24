package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"ctfuzz/internal/result"
)

func runReport(args []string) error {
	fs := flag.NewFlagSet("ctfuzz report", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		jsonlPath string
		format    string
		minScore  int
		all       bool
	)
	fs.StringVar(&jsonlPath, "jsonl", "", "scan results JSONL (required)")
	fs.StringVar(&format, "format", "markdown", "output format: markdown or json")
	fs.IntVar(&minScore, "min-score", 0, "only include summaries at or above this score")
	fs.BoolVar(&all, "all", false, "include uninteresting summaries too (default shows interesting only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if jsonlPath == "" {
		return errors.New("--jsonl is required")
	}
	switch format {
	case "markdown", "json":
	default:
		return fmt.Errorf("unsupported --format %q", format)
	}

	manifest, requests, summaries, err := loadJSONL(jsonlPath)
	if err != nil {
		return err
	}
	selected := selectSummaries(summaries, minScore, all)

	switch format {
	case "json":
		return writeJSONReport(manifest, selected, requests)
	default:
		return writeMarkdownReport(manifest, selected, requests)
	}
}

func selectSummaries(all []result.Summary, minScore int, includeAll bool) []result.Summary {
	out := make([]result.Summary, 0, len(all))
	for _, s := range all {
		if !includeAll && !s.Interesting {
			continue
		}
		if s.Score < minScore {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].URL != out[j].URL {
			return out[i].URL < out[j].URL
		}
		return out[i].Method < out[j].Method
	})
	return out
}

func writeJSONReport(manifest result.Manifest, summaries []result.Summary, _ []result.Request) error {
	out := map[string]any{
		"manifest":  manifest,
		"summaries": summaries,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeMarkdownReport(manifest result.Manifest, summaries []result.Summary, requests []result.Request) error {
	byKey := map[string][]result.Request{}
	for _, r := range requests {
		byKey[r.URL+" "+r.Method] = append(byKey[r.URL+" "+r.Method], r)
	}
	w := os.Stdout

	fmt.Fprintln(w, "# ctfuzz report")
	fmt.Fprintln(w)
	if manifest.Created != "" {
		fmt.Fprintf(w, "- created: `%s`\n", manifest.Created)
	}
	if len(manifest.Methods) > 0 {
		fmt.Fprintf(w, "- methods: `%s`\n", strings.Join(manifest.Methods, ","))
	}
	if manifest.Mismatch {
		fmt.Fprintln(w, "- mismatch: enabled")
	}
	if manifest.Canary != "" {
		fmt.Fprintf(w, "- canary: `%s`\n", manifest.Canary)
	}
	fmt.Fprintf(w, "- findings: %d\n\n", len(summaries))

	if len(summaries) == 0 {
		fmt.Fprintln(w, "_No findings above the filter threshold._")
		return nil
	}
	for _, s := range summaries {
		header := s.URL
		if s.Method != "" {
			header = s.Method + " " + s.URL
		}
		fmt.Fprintf(w, "## %s\n\n", header)
		fmt.Fprintf(w, "- score: %d\n", s.Score)
		fmt.Fprintf(w, "- reason: %s\n", s.Reason)
		if len(s.Statuses) > 0 {
			fmt.Fprintf(w, "- statuses: %s\n", formatStatuses(s.Statuses))
		}
		fmt.Fprintln(w)
		if len(s.HeaderGroups) > 0 {
			fmt.Fprintln(w, "### header clusters")
			fmt.Fprintln(w)
			for i, g := range s.HeaderGroups {
				fmt.Fprintf(w, "- **%c** (%d cts): %s\n", 'A'+i, len(g.ContentTypes), truncate(strings.Join(g.ContentTypes, ", "), 160))
				if len(g.Headers) > 0 {
					keys := make([]string, 0, len(g.Headers))
					for k := range g.Headers {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					for _, k := range keys {
						fmt.Fprintf(w, "    - `%s: %s`\n", k, truncate(g.Headers[k], 200))
					}
				}
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "### replay\n\n```sh\nctfuzz replay --jsonl RESULTS --url %s --method %s\n```\n\n",
			shellQuote(s.URL), s.Method)
	}
	return nil
}

func formatStatuses(statuses map[string]int) string {
	keys := make([]string, 0, len(statuses))
	for k := range statuses {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// Group by status.
	byStatus := map[int][]string{}
	for _, k := range keys {
		byStatus[statuses[k]] = append(byStatus[statuses[k]], k)
	}
	codes := make([]int, 0, len(byStatus))
	for c := range byStatus {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	parts := make([]string, 0, len(codes))
	for _, c := range codes {
		names := byStatus[c]
		if len(names) > 4 {
			parts = append(parts, fmt.Sprintf("%d=%d variants", c, len(names)))
			continue
		}
		parts = append(parts, fmt.Sprintf("%d=%s", c, strings.Join(names, ",")))
	}
	return strings.Join(parts, "  ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
