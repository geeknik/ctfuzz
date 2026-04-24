package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"ctfuzz/internal/payload"
	"ctfuzz/internal/render"
	"ctfuzz/internal/result"
)

func runReplay(args []string) error {
	fs := flag.NewFlagSet("ctfuzz replay", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		jsonlPath   string
		payloadPath string
		seq         int
		urlFilter   string
		methodOnly  string
		variantOnly string
		onlyFindings bool
	)
	fs.StringVar(&jsonlPath, "jsonl", "", "scan results JSONL (required)")
	fs.StringVar(&payloadPath, "payload", "", "payload.json used for the scan (required for body reconstruction)")
	fs.IntVar(&seq, "seq", -1, "pick the request at this sequence number")
	fs.StringVar(&urlFilter, "url", "", "pick requests whose URL equals or contains this value")
	fs.StringVar(&methodOnly, "method", "", "restrict to this HTTP method")
	fs.StringVar(&variantOnly, "variant", "", "restrict to this variant name (e.g. application/json or json-as-xml)")
	fs.BoolVar(&onlyFindings, "interesting-only", false, "only replay requests from summaries marked interesting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if jsonlPath == "" {
		return errors.New("--jsonl is required")
	}

	manifest, requests, summaries, err := loadJSONL(jsonlPath)
	if err != nil {
		return err
	}

	matches := filterRequests(requests, summaries, seq, urlFilter, methodOnly, variantOnly, onlyFindings)
	if len(matches) == 0 {
		return errors.New("no requests matched the replay selector")
	}

	// Rebuild the logical payload (with the same canary) so re-rendered
	// bodies are byte-identical where possible.
	var payloadObj map[string]any
	if payloadPath != "" {
		payloadObj, err = payload.Load(payloadPath, 1024*1024, manifest.Canary)
		if err != nil {
			return fmt.Errorf("reload payload: %w", err)
		}
	}

	for i, r := range matches {
		if i > 0 {
			fmt.Println()
		}
		printCurl(r, payloadObj)
	}
	return nil
}

func filterRequests(reqs []result.Request, summaries []result.Summary, seq int, url, method, variant string, onlyFindings bool) []result.Request {
	interesting := map[string]bool{}
	if onlyFindings {
		for _, s := range summaries {
			if s.Interesting {
				interesting[s.URL+" "+s.Method] = true
			}
		}
	}
	out := make([]result.Request, 0, len(reqs))
	for _, r := range reqs {
		if seq >= 0 && r.Seq != seq {
			continue
		}
		if url != "" && !strings.Contains(r.URL, url) {
			continue
		}
		if method != "" && !strings.EqualFold(r.Method, method) {
			continue
		}
		if variant != "" && r.VariantName != variant && r.ContentType != variant {
			continue
		}
		if onlyFindings && !interesting[r.URL+" "+r.Method] {
			continue
		}
		out = append(out, r)
	}
	return out
}

func printCurl(r result.Request, payloadObj map[string]any) {
	var body []byte
	if payloadObj != nil && r.BodyEncoding != "" {
		// Prefer BodyAs for json/xml/form; fall back to Body for multipart/yaml/etc.
		if b, err := render.BodyAs(r.BodyEncoding, payloadObj); err == nil {
			body = b
		} else if b, err := render.Body(r.ContentType, payloadObj); err == nil {
			body = b
		}
	}

	fmt.Printf("# seq=%d %s %s variant=%s status=%d\n",
		r.Seq, r.Method, r.URL, r.VariantName, r.Status)
	fmt.Printf("curl -sS -X %s", shellQuote(r.Method))
	fmt.Printf(" \\\n  -H %s", shellQuote("User-Agent: ctfuzz-replay/0.1"))
	fmt.Printf(" \\\n  -H %s", shellQuote("Accept: */*"))
	if r.ContentType != "" {
		fmt.Printf(" \\\n  -H %s", shellQuote("Content-Type: "+r.ContentType))
	}
	if len(body) > 0 {
		fmt.Printf(" \\\n  --data-binary %s", shellQuote(string(body)))
	} else if payloadObj == nil {
		fmt.Printf(" \\\n  # NOTE: pass --payload to reconstruct the request body")
	}
	fmt.Printf(" \\\n  %s\n", shellQuote(r.URL))
}

// shellQuote wraps a value in single quotes for POSIX shells; any embedded
// single quote is encoded as '"'"' — the idiomatic escape that works in
// bash, zsh, dash, and ash.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func loadJSONL(path string) (result.Manifest, []result.Request, []result.Summary, error) {
	f, err := os.Open(path)
	if err != nil {
		return result.Manifest{}, nil, nil, err
	}
	defer f.Close()

	var (
		manifest  result.Manifest
		requests  []result.Request
		summaries []result.Summary
	)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		var peek struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &peek); err != nil {
			return result.Manifest{}, nil, nil, fmt.Errorf("decode line: %w", err)
		}
		switch peek.Kind {
		case "manifest":
			if err := json.Unmarshal(scanner.Bytes(), &manifest); err != nil {
				return result.Manifest{}, nil, nil, fmt.Errorf("decode manifest: %w", err)
			}
		case "summary":
			var s result.Summary
			if err := json.Unmarshal(scanner.Bytes(), &s); err != nil {
				return result.Manifest{}, nil, nil, fmt.Errorf("decode summary: %w", err)
			}
			summaries = append(summaries, s)
		default:
			var r result.Request
			if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
				return result.Manifest{}, nil, nil, fmt.Errorf("decode request: %w", err)
			}
			requests = append(requests, r)
		}
	}
	if err := scanner.Err(); err != nil {
		return result.Manifest{}, nil, nil, err
	}
	return manifest, requests, summaries, nil
}

