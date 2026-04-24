package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"ctfuzz/internal/analyze"
	"ctfuzz/internal/config"
	"ctfuzz/internal/httpclient"
	"ctfuzz/internal/input"
	"ctfuzz/internal/output"
	"ctfuzz/internal/payload"
	"ctfuzz/internal/render"
	"ctfuzz/internal/result"
	"ctfuzz/internal/scope"

	"net/url"
)

var errScopeViolation = errors.New("out-of-scope URLs detected; pass --allow-scope-drops to continue")

type job struct {
	seq          int
	url          string
	method       string
	variant      string
	contentType string
	omitCT       bool
	bodyEncoding string
	body         []byte
}

// Exit codes are a stable contract for agent pipelines:
//
//	0  clean run, no interesting findings
//	1  unexpected error (config, IO, network infrastructure)
//	2  CLI usage error (reserved; flag pkg maps to 2 on its own)
//	3  scope violation (URLs outside --scope-file; --allow-scope-drops bypasses)
//	4  clean run, interesting findings present
const (
	exitOK           = 0
	exitError        = 1
	exitScope        = 3
	exitFindings     = 4
)

func main() {
	args := os.Args[1:]
	sub, rest := peelSubcommand(args)

	var (
		hasFindings bool
		err         error
	)
	switch sub {
	case "scan", "":
		hasFindings, err = run(rest)
	case "replay":
		err = runReplay(rest)
	case "report":
		err = runReport(rest)
	case "help", "-h", "--help":
		printTopHelp()
		return
	default:
		fmt.Fprintf(os.Stderr, "ctfuzz: unknown subcommand %q (try: scan, replay, report)\n", sub)
		os.Exit(exitError)
	}

	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(exitOK)
		}
		if errors.Is(err, errScopeViolation) {
			fmt.Fprintf(os.Stderr, "ctfuzz: %v\n", err)
			os.Exit(exitScope)
		}
		fmt.Fprintf(os.Stderr, "ctfuzz: %v\n", err)
		os.Exit(exitError)
	}
	if hasFindings {
		os.Exit(exitFindings)
	}
}

// peelSubcommand detects a leading subcommand token. A bare word matching a
// known subcommand consumes args[0]; anything else is treated as flags to
// the default "scan" command.
func peelSubcommand(args []string) (string, []string) {
	if len(args) == 0 {
		return "", args
	}
	first := args[0]
	if strings.HasPrefix(first, "-") {
		return "", args
	}
	switch first {
	case "scan", "replay", "report", "help":
		return first, args[1:]
	}
	return "", args
}

func printTopHelp() {
	fmt.Fprint(os.Stderr, `ctfuzz — content-type differential fuzzer

usage:
  ctfuzz [scan] [flags]         run a scan (default)
  ctfuzz replay  [flags]        print a reproducible curl for one request
  ctfuzz report  [flags]        summarize a scan JSONL as markdown or json

exit codes:
  0  clean run, no findings
  1  unexpected error
  3  scope violation
  4  clean run, interesting findings present

Run 'ctfuzz scan -h', 'ctfuzz replay -h', or 'ctfuzz report -h' for per-subcommand flags.
`)
}

func run(args []string) (bool, error) {
	cfg, err := config.Parse(args, os.Stderr)
	if err != nil {
		return false, err
	}

	urls, err := input.LoadURLs(cfg.URLsFile)
	if err != nil {
		return false, err
	}
	fmt.Printf("[+] loaded %d urls\n", len(urls))

	if cfg.ScopeFile != "" {
		matcher, err := scope.Load(cfg.ScopeFile)
		if err != nil {
			return false, fmt.Errorf("scope file: %w", err)
		}
		kept, dropped := applyScope(matcher, urls)
		if len(dropped) > 0 {
			fmt.Fprintf(os.Stderr, "[!] scope filter dropped %d URLs:\n", len(dropped))
			for _, u := range dropped {
				fmt.Fprintf(os.Stderr, "    %s\n", u)
			}
			if !cfg.AllowScopeDrops {
				return false, errScopeViolation
			}
		}
		urls = kept
		if len(urls) == 0 {
			return false, errors.New("all URLs were dropped by scope filter")
		}
		fmt.Printf("[+] %d urls within scope\n", len(urls))
	}

	headers, err := input.LoadHeaders(cfg.HeadersFile)
	if err != nil {
		return false, err
	}
	if len(headers) > 0 {
		fmt.Printf("[+] loaded %d static headers\n", len(headers))
	}

	basePayload, err := payload.Load(cfg.PayloadFile, cfg.MaxRequestBody, cfg.Canary)
	if err != nil {
		return false, err
	}
	fmt.Printf("[+] loaded payload with %d keys\n", len(basePayload))

	variants, err := buildVariants(cfg, basePayload)
	if err != nil {
		return false, err
	}
	fmt.Printf("[+] testing %d variants across %d method(s) per URL\n", len(variants), len(cfg.Methods))
	if cfg.Insecure {
		fmt.Println("[!] TLS certificate verification disabled")
	}

	plan := buildPlan(cfg, urls)
	printRunPlan(plan, cfg, basePayload)

	if cfg.DryRun {
		fmt.Println("[+] dry run complete; no requests sent")
		return false, nil
	}

	client, err := httpclient.New(httpclient.Config{
		Timeout:           cfg.Timeout,
		Proxy:             cfg.Proxy,
		Insecure:          cfg.Insecure,
		FollowRedirects:   cfg.FollowRedirects,
		MaxBodyRead:       cfg.MaxBodyRead,
		IncludeBody:       cfg.IncludeBody,
		Canary:            cfg.Canary,
		Retries:           cfg.Retries,
		RetryBackoff:      cfg.RetryBackoff,
		RequestsPerSecond: cfg.RequestsPerSecond,
	})
	if err != nil {
		return false, err
	}

	results := execute(context.Background(), client, cfg, urls, headers, variants)
	summaries := summarize(urls, cfg.Methods, results)
	summaryByKey := make(map[string]result.Summary, len(summaries))
	hasFindings := false
	for _, summary := range summaries {
		summaryByKey[summaryKey(summary.URL, summary.Method)] = summary
		if summary.Interesting {
			hasFindings = true
		}
	}
	analyze.MarkInteresting(results, summaryByKey)

	multiMethod := len(cfg.Methods) > 1
	for _, summary := range summaries {
		if summary.Interesting {
			prefix := "[!] interesting"
			if multiMethod {
				fmt.Printf("%s %s %s score=%d %s\n", prefix, summary.Method, summary.URL, summary.Score, analyze.ConsoleStatus(summary))
			} else {
				fmt.Printf("%s %s score=%d %s\n", prefix, summary.URL, summary.Score, analyze.ConsoleStatus(summary))
			}
			if cfg.Verbose {
				fmt.Printf("    reason: %s\n", summary.Reason)
			}
			printHeaderGroups(summary, cfg.Verbose)
		}
	}

	manifest := result.Manifest{
		Kind:     "manifest",
		Schema:   1,
		Created:  time.Now().UTC().Format(time.RFC3339),
		Canary:   cfg.Canary,
		Methods:  cfg.Methods,
		Types:    cfg.Types,
		Mismatch: cfg.Mismatch,
	}
	if err := output.WriteJSONL(cfg.OutputFile, manifest, results, summaries); err != nil {
		return false, err
	}
	fmt.Printf("[+] wrote results to %s\n", cfg.OutputFile)
	return hasFindings, nil
}

type variant struct {
	Name         string // display name / VariantName
	ContentType  string // header to send; "" when OmitCT is true
	OmitCT       bool
	BodyEncoding string
	Body         []byte
}

func buildVariants(cfg config.Config, basePayload map[string]any) ([]variant, error) {
	out := make([]variant, 0, len(cfg.Types)+len(render.MismatchScenarios))
	// Natural variants: one per --types entry, body matches header family.
	for _, ct := range cfg.Types {
		body, err := render.Body(ct, basePayload)
		if err != nil {
			return nil, err
		}
		if int64(len(body)) > cfg.MaxRequestBody {
			return nil, fmt.Errorf("%s request body exceeds %d bytes", ct, cfg.MaxRequestBody)
		}
		out = append(out, variant{
			Name:         ct,
			ContentType:  ct,
			BodyEncoding: render.EncodingFor(ct),
			Body:         body,
		})
	}
	// Mismatch variants: body encoding deliberately disagrees with header.
	if cfg.Mismatch {
		for _, s := range render.MismatchScenarios {
			body, err := render.BodyAs(s.Encoding, basePayload)
			if err != nil {
				return nil, err
			}
			if int64(len(body)) > cfg.MaxRequestBody {
				return nil, fmt.Errorf("mismatch %s body exceeds %d bytes", s.Name, cfg.MaxRequestBody)
			}
			out = append(out, variant{
				Name:         s.Name,
				ContentType:  s.Header,
				OmitCT:       s.Header == "",
				BodyEncoding: s.Encoding,
				Body:         body,
			})
		}
	}
	return out, nil
}

func execute(ctx context.Context, client *httpclient.Client, cfg config.Config, urls []string, headers http.Header, variants []variant) []result.Request {
	jobs := make(chan job)
	resultsCh := make(chan result.Request)

	var wg sync.WaitGroup
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				req := httpclient.RequestSpec{
					Seq:         item.seq,
					URL:         item.url,
					Method:      item.method,
					ContentType: item.contentType,
					OmitCT:      item.omitCT,
					Body:        item.body,
					Headers:     headers,
				}
				res := client.Do(ctx, req)
				res.Method = item.method
				res.ContentType = item.contentType
				res.VariantName = item.variant
				res.BodyEncoding = item.bodyEncoding
				resultsCh <- res
				if cfg.Verbose {
					fmt.Printf("[.] %s %s %s status=%d error=%q\n", item.method, item.url, item.variant, res.Status, res.Error)
				}
				if cfg.Delay > 0 {
					time.Sleep(cfg.Delay)
				}
			}
		}()
	}

	hostCount := map[string]int{}
	skipped := 0
	go func() {
		seq := 0
		for _, targetURL := range urls {
			host := hostKey(targetURL)
			for _, method := range cfg.Methods {
				for _, v := range variants {
					if cfg.MaxRequestsPerHost > 0 && hostCount[host] >= cfg.MaxRequestsPerHost {
						skipped++
						continue
					}
					hostCount[host]++
					jobs <- job{
						seq:          seq,
						url:          targetURL,
						method:       method,
						variant:      v.Name,
						contentType:  v.ContentType,
						omitCT:       v.OmitCT,
						bodyEncoding: v.BodyEncoding,
						body:         v.Body,
					}
					seq++
				}
			}
		}
		close(jobs)
		wg.Wait()
		close(resultsCh)
	}()

	results := make([]result.Request, 0, len(urls)*len(cfg.Methods)*len(variants))
	for res := range resultsCh {
		results = append(results, res)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Seq < results[j].Seq
	})
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "[!] max-requests-per-host dropped %d jobs\n", skipped)
	}
	return results
}

func printHeaderGroups(summary result.Summary, verbose bool) {
	if len(summary.HeaderGroups) == 0 {
		return
	}
	labels := make([]string, 0, len(summary.HeaderGroups))
	for i, g := range summary.HeaderGroups {
		labels = append(labels, fmt.Sprintf("%c(%d)", 'A'+i, len(g.ContentTypes)))
	}
	diffKeys := differingHeaderNames(summary.HeaderGroups)
	line := "    header clusters: " + strings.Join(labels, ", ")
	if len(diffKeys) > 0 {
		line += " [" + strings.Join(diffKeys, ", ") + "]"
	} else {
		line += " (delta outside triage whitelist — inspect raw headers via proxy)"
	}
	fmt.Println(line)
	if !verbose {
		return
	}
	for i, g := range summary.HeaderGroups {
		members := compactContentTypes(g.ContentTypes)
		fmt.Printf("      %c (%d cts): %s\n", 'A'+i, len(g.ContentTypes), members)
		for _, name := range diffKeys {
			fmt.Printf("          %s: %s\n", name, g.Headers[name])
		}
	}
}

func differingHeaderNames(groups []result.HeaderGroup) []string {
	names := map[string]struct{}{}
	for _, g := range groups {
		for name := range g.Headers {
			names[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func compactContentTypes(cts []string) string {
	const limit = 4
	if len(cts) <= limit {
		return strings.Join(cts, ", ")
	}
	return strings.Join(cts[:limit], ", ") + fmt.Sprintf(", +%d", len(cts)-limit)
}

func applyScope(matcher *scope.Matcher, urls []string) (kept, dropped []string) {
	kept = make([]string, 0, len(urls))
	for _, u := range urls {
		if matcher.AllowsURL(u) {
			kept = append(kept, u)
		} else {
			dropped = append(dropped, u)
		}
	}
	return kept, dropped
}

func hostKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return strings.ToLower(u.Hostname())
}

type runPlan struct {
	Hosts           []string
	PerHost         map[string]int
	URLs            int
	Types           int
	MismatchCount   int
	VariantsPerURL  int
	Methods         []string
	Requests        int
	DryRun          bool
	CanaryTag       string
}

func buildPlan(cfg config.Config, urls []string) runPlan {
	mismatchCount := 0
	if cfg.Mismatch {
		mismatchCount = len(render.MismatchScenarios)
	}
	variantsPerURL := len(cfg.Types) + mismatchCount
	perURLRequests := variantsPerURL * len(cfg.Methods)

	plan := runPlan{
		PerHost:        map[string]int{},
		URLs:           len(urls),
		Types:          len(cfg.Types),
		MismatchCount:  mismatchCount,
		VariantsPerURL: variantsPerURL,
		Methods:        cfg.Methods,
		DryRun:         cfg.DryRun,
		CanaryTag:      cfg.Canary,
	}
	hosts := map[string]struct{}{}
	for _, u := range urls {
		host := hostKey(u)
		hosts[host] = struct{}{}
		n := perURLRequests
		if cfg.MaxRequestsPerHost > 0 {
			remaining := cfg.MaxRequestsPerHost - plan.PerHost[host]
			if remaining < 0 {
				remaining = 0
			}
			if n > remaining {
				n = remaining
			}
		}
		plan.PerHost[host] += n
		plan.Requests += n
	}
	plan.Hosts = make([]string, 0, len(hosts))
	for h := range hosts {
		plan.Hosts = append(plan.Hosts, h)
	}
	sort.Strings(plan.Hosts)
	return plan
}

func printRunPlan(plan runPlan, cfg config.Config, basePayload map[string]any) {
	heading := "[+] plan"
	if plan.DryRun {
		heading = "[+] dry-run plan"
	}
	methodList := strings.Join(plan.Methods, ",")
	fmt.Printf("%s: methods=%s %d urls × %d variants",
		heading, methodList, plan.URLs, plan.VariantsPerURL)
	if plan.MismatchCount > 0 {
		fmt.Printf(" (%d base + %d mismatch)", plan.Types, plan.MismatchCount)
	}
	fmt.Printf(" × %d methods = %d requests across %d host(s)\n",
		len(plan.Methods), plan.Requests, len(plan.Hosts))
	if cfg.MaxRequestsPerHost > 0 {
		fmt.Printf("    per-host cap: %d\n", cfg.MaxRequestsPerHost)
	}
	if cfg.RequestsPerSecond > 0 {
		fmt.Printf("    rate: %.2f rps per host (burst %d)\n", cfg.RequestsPerSecond, int(cfg.RequestsPerSecond))
	}
	if cfg.Canary != "" {
		fmt.Printf("    canary: %s\n", cfg.Canary)
	}
	mutating := []string{}
	for _, m := range plan.Methods {
		if isMutatingMethod(m) {
			mutating = append(mutating, m)
		}
	}
	if len(mutating) > 0 {
		fmt.Printf("[!] %s requests will send a %d-key payload body to each target; this may mutate target state\n",
			strings.Join(mutating, ","), len(basePayload))
	}
	if plan.DryRun {
		for _, host := range plan.Hosts {
			fmt.Printf("    %-40s %d requests\n", host, plan.PerHost[host])
		}
	}
}

func isMutatingMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func summaryKey(url, method string) string {
	return analyze.SummaryKey(url, method)
}

func summarize(urls, methods []string, requests []result.Request) []result.Summary {
	grouped := make(map[string][]result.Request, len(urls)*len(methods))
	for _, req := range requests {
		grouped[analyze.SummaryKey(req.URL, req.Method)] = append(grouped[analyze.SummaryKey(req.URL, req.Method)], req)
	}

	summaries := make([]result.Summary, 0, len(urls)*len(methods))
	for _, targetURL := range urls {
		for _, method := range methods {
			key := analyze.SummaryKey(targetURL, method)
			if len(grouped[key]) == 0 {
				continue
			}
			s := analyze.Summarize(targetURL, grouped[key])
			s.Method = method
			summaries = append(summaries, s)
		}
	}
	return summaries
}
