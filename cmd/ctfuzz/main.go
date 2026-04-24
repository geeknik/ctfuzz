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
)

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

	go func() {
		seq := 0
		for _, targetURL := range urls {
			for _, contentType := range cfg.Types {
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

	total := len(urls) * len(cfg.Types)
	results := make([]result.Request, 0, total)
	for res := range resultsCh {
		results = append(results, res)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Seq < results[j].Seq
	})
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
