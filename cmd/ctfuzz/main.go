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
	seq         int
	url         string
	contentType string
	body        []byte
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		if errors.Is(err, errScopeViolation) {
			fmt.Fprintf(os.Stderr, "ctfuzz: %v\n", err)
			os.Exit(3)
		}
		fmt.Fprintf(os.Stderr, "ctfuzz: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := config.Parse(args, os.Stderr)
	if err != nil {
		return err
	}

	urls, err := input.LoadURLs(cfg.URLsFile)
	if err != nil {
		return err
	}
	fmt.Printf("[+] loaded %d urls\n", len(urls))

	if cfg.ScopeFile != "" {
		matcher, err := scope.Load(cfg.ScopeFile)
		if err != nil {
			return fmt.Errorf("scope file: %w", err)
		}
		kept, dropped := applyScope(matcher, urls)
		if len(dropped) > 0 {
			fmt.Fprintf(os.Stderr, "[!] scope filter dropped %d URLs:\n", len(dropped))
			for _, u := range dropped {
				fmt.Fprintf(os.Stderr, "    %s\n", u)
			}
			if !cfg.AllowScopeDrops {
				return errScopeViolation
			}
		}
		urls = kept
		if len(urls) == 0 {
			return errors.New("all URLs were dropped by scope filter")
		}
		fmt.Printf("[+] %d urls within scope\n", len(urls))
	}

	headers, err := input.LoadHeaders(cfg.HeadersFile)
	if err != nil {
		return err
	}
	if len(headers) > 0 {
		fmt.Printf("[+] loaded %d static headers\n", len(headers))
	}

	basePayload, err := payload.Load(cfg.PayloadFile, cfg.MaxRequestBody, cfg.Canary)
	if err != nil {
		return err
	}
	fmt.Printf("[+] loaded payload with %d keys\n", len(basePayload))

	bodies := map[string][]byte{}
	for _, contentType := range cfg.Types {
		body, err := render.Body(contentType, basePayload)
		if err != nil {
			return err
		}
		if int64(len(body)) > cfg.MaxRequestBody {
			return fmt.Errorf("%s request body exceeds %d bytes", contentType, cfg.MaxRequestBody)
		}
		bodies[contentType] = body
	}
	fmt.Printf("[+] testing %d content-types per URL\n", len(cfg.Types))
	if cfg.Insecure {
		fmt.Println("[!] TLS certificate verification disabled")
	}

	plan := buildPlan(cfg, urls)
	printRunPlan(plan, cfg, basePayload)

	if cfg.DryRun {
		fmt.Println("[+] dry run complete; no requests sent")
		return nil
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
		return err
	}

	results := execute(context.Background(), client, cfg, urls, headers, bodies)
	summaries := summarize(urls, results)
	summaryByURL := make(map[string]result.Summary, len(summaries))
	for _, summary := range summaries {
		summaryByURL[summary.URL] = summary
	}
	analyze.MarkInteresting(results, summaryByURL)

	for _, summary := range summaries {
		if summary.Interesting {
			fmt.Printf("[!] interesting %s score=%d %s\n", summary.URL, summary.Score, analyze.ConsoleStatus(summary))
			if cfg.Verbose {
				fmt.Printf("    reason: %s\n", summary.Reason)
			}
			printHeaderGroups(summary, cfg.Verbose)
		}
	}

	if err := output.WriteJSONL(cfg.OutputFile, results, summaries); err != nil {
		return err
	}
	fmt.Printf("[+] wrote results to %s\n", cfg.OutputFile)
	return nil
}

func execute(ctx context.Context, client *httpclient.Client, cfg config.Config, urls []string, headers http.Header, bodies map[string][]byte) []result.Request {
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
					Method:      cfg.Method,
					ContentType: item.contentType,
					Body:        item.body,
					Headers:     headers,
				}
				res := client.Do(ctx, req)
				resultsCh <- res
				if cfg.Verbose {
					fmt.Printf("[.] %s %s %s status=%d error=%q\n", cfg.Method, item.url, render.ShortName(item.contentType), res.Status, res.Error)
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
			for _, contentType := range cfg.Types {
				if cfg.MaxRequestsPerHost > 0 && hostCount[host] >= cfg.MaxRequestsPerHost {
					skipped++
					continue
				}
				hostCount[host]++
				jobs <- job{
					seq:         seq,
					url:         targetURL,
					contentType: contentType,
					body:        bodies[contentType],
				}
				seq++
			}
		}
		close(jobs)
		wg.Wait()
		close(resultsCh)
	}()

	results := make([]result.Request, 0, len(urls)*len(cfg.Types))
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
	Hosts     []string
	PerHost   map[string]int
	PerType   map[string]int
	URLs      int
	Types     int
	Requests  int
	Method    string
	DryRun    bool
	CanaryTag string
}

func buildPlan(cfg config.Config, urls []string) runPlan {
	plan := runPlan{
		PerHost:  map[string]int{},
		PerType:  map[string]int{},
		URLs:     len(urls),
		Types:    len(cfg.Types),
		Method:   cfg.Method,
		DryRun:   cfg.DryRun,
		CanaryTag: cfg.Canary,
	}
	hosts := map[string]struct{}{}
	for _, u := range urls {
		host := hostKey(u)
		hosts[host] = struct{}{}
		n := len(cfg.Types)
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
	for _, ct := range cfg.Types {
		plan.PerType[ct] = plan.URLs
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
	fmt.Printf("%s: %s %d urls × %d content-types = %d requests across %d host(s)\n",
		heading, plan.Method, plan.URLs, plan.Types, plan.Requests, len(plan.Hosts))
	if cfg.MaxRequestsPerHost > 0 {
		fmt.Printf("    per-host cap: %d\n", cfg.MaxRequestsPerHost)
	}
	if cfg.RequestsPerSecond > 0 {
		fmt.Printf("    rate: %.2f rps per host (burst %d)\n", cfg.RequestsPerSecond, int(cfg.RequestsPerSecond))
	}
	if cfg.Canary != "" {
		fmt.Printf("    canary: %s\n", cfg.Canary)
	}
	if isMutatingMethod(plan.Method) {
		fmt.Printf("[!] %s requests will send a %d-key payload body to each target; this may mutate target state\n",
			plan.Method, len(basePayload))
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

func summarize(urls []string, requests []result.Request) []result.Summary {
	grouped := make(map[string][]result.Request, len(urls))
	for _, req := range requests {
		grouped[req.URL] = append(grouped[req.URL], req)
	}

	summaries := make([]result.Summary, 0, len(urls))
	for _, targetURL := range urls {
		summaries = append(summaries, analyze.Summarize(targetURL, grouped[targetURL]))
	}
	return summaries
}
