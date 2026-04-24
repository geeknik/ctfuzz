# ctfuzz

Content-type differential fuzzer for authorized web application testing and
bug bounty work. Given a list of known URLs, ctfuzz sends the same logical
payload through many body encodings and `Content-Type` headers, then surfaces
the routes that behave differently across variants.

The tool is narrow by design.

## What it is

- A tool that highlights **parser disagreement** between what the edge sees
  and what the backend accepts.
- A tool that surfaces **content-type-sensitive authorization** — a route
  that rejects JSON but accepts form data is a bug shape ctfuzz was built
  to find.
- A tool that records structured JSONL and exits with stable codes so an
  agent pipeline can act on findings without parsing stdout.

## What it is not

- A general-purpose HTTP fuzzer.
- A URL or parameter discovery engine — bring your own URL list.
- A payload generator for XXE/SSRF/SQLi. ctfuzz sends the *same* logical
  payload every time by design; the value is in the delta across encodings.
- A WAF bypass framework.
- A load tester.

## Install

```sh
git clone git@github.com:geeknik/ctfuzz.git
cd ctfuzz
go build -o ctfuzz ./cmd/ctfuzz
```

Requires Go 1.22+. No runtime dependencies.

## Quickstart

```sh
cat > urls.txt <<'EOF'
https://in-scope.example.com/api/user
https://in-scope.example.com/api/search
EOF

cat > payload.json <<'EOF'
{ "id": "1", "role": "user", "admin": false }
EOF

cat > scope.txt <<'EOF'
in-scope.example.com
*.in-scope.example.com
EOF

# Plan the run — no network traffic.
./ctfuzz --urls urls.txt --payload payload.json \
         --scope-file scope.txt --dry-run

# Run it through Burp, with a per-host rate cap.
./ctfuzz --urls urls.txt --payload payload.json \
         --scope-file scope.txt \
         --proxy http://127.0.0.1:8080 \
         --rps 5 \
         --out results.jsonl

# Summarize findings.
./ctfuzz report --jsonl results.jsonl > findings.md

# Reproduce one interesting request as a curl command.
./ctfuzz replay --jsonl results.jsonl --payload payload.json --seq 7
```

## Subcommands

| Subcommand | Purpose |
| ---------- | ------- |
| `scan` (default) | Run the content-type differential matrix |
| `replay` | Print a reproducible `curl` for one request from a results file |
| `report` | Summarize `results.jsonl` as markdown or JSON |
| `help` | Print top-level help |

Bare `ctfuzz [flags]` is equivalent to `ctfuzz scan [flags]`.

## Safety defaults

ctfuzz assumes it is being pointed at live targets that an operator cares
about. The defaults reflect that posture:

- No redirect following, no retries, bounded concurrency (8), 10s timeout.
- `--rps 0` (off) — set this explicitly for real targets.
- `--scope-file` enforces a host allowlist. Any out-of-scope URL aborts
  the run with exit code 3 unless `--allow-scope-drops` is set.
- `--max-requests-per-host N` hard-caps blast radius per host.
- `--dry-run` prints the request matrix and exits without any network
  traffic, including URL counts per host and the total request volume.
- Canary is a 16-hex random token with no fixed prefix (no WAF-
  fingerprintable tell). `--canary-prefix` adds a marker if you want one
  for log correlation.
- POST/PUT/PATCH/DELETE emit a prominent notice at run start with the
  payload key count, so it's obvious when a run will mutate target state.
- JSONL output is written atomically at mode 0600.

## Coverage modes

### 35 content-type variants by default

Covers the JSON family (`application/json`, `vnd.api+json`, `hal+json`,
`ld+json`, `json-patch+json`, `merge-patch+json`, `problem+json`,
`scim+json`, `activity+json`, `manifest+json`, `reports+json`,
`csp-report`, `text/json`, `x-json`, `x-ndjson`), the XML family
(`application/xml`, `text/xml`, `soap+xml`, `atom+xml`, `rss+xml`, plus
charset variants), form + multipart, the YAML family, `text/plain`,
`application/javascript`, `text/javascript`, and `application/octet-stream`.

```sh
ctfuzz --types all          # default — all 35
ctfuzz --types core         # just application/json, application/xml, form
ctfuzz --types json-family  # JSON and JSON-ish only
```

### `--methods`

Run the full variant matrix across multiple HTTP methods for compound
differential analysis.

```sh
ctfuzz --methods POST,PUT,PATCH,DELETE,GET ...
```

The analyzer groups by `(URL, method)`, so each method has its own
summary line and its own clustering analysis.

### `--mismatch`

Additive opt-in. Appends 9 body/Content-Type disagreement scenarios per
URL per method so you can probe parser-disagreement bugs:

```
json-as-xml   json-as-form    json-as-plain   json-no-header
xml-as-json   xml-as-form
form-as-json  form-as-xml     form-no-header
```

`*-no-header` variants actually omit the `Content-Type` header end-to-end,
not replace it with an empty string.

## Differential detection

Each URL's variants are compared on:

- Status code distribution
- Response body SHA-256
- Response header fingerprint
- Response size and duration
- Redirect location and host
- Canary reflection
- Parser/framework error keywords

URLs are scored 0–100. Summaries are promoted to `interesting` when at
least one **reportable** signal fires. Fingerprint-only noise (varying
`Date`, per-request request-IDs) is scored but suppressed from the
`interesting` flag — it still lands in the JSONL so agents can inspect
the full signal set.

### Structural header clustering

ctfuzz's most distinctive signal. When response headers cluster cleanly
into a small number of groups (e.g., 24 content types see one header
set, 11 see another) and each group has ≥ 2 members, that's
deterministic behavior, not jitter. The structural signal:

- Scores +25 (reportable).
- Populates `summary.header_groups` in the JSONL with each group's
  content-type list and the subset of whitelisted response headers whose
  values actually differ across groups.
- Prints a compact cluster line on the console and a full breakdown in
  verbose mode.

The triage-header whitelist covers `Server`, `X-Powered-By`, `Vary`,
`Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`,
CORS family, `Set-Cookie` names only (no values), `Retry-After`,
`X-RateLimit-*`, `Reporting-Endpoints`, `Server-Timing`, and ~30 others.
Cookie values and per-request identifiers are never captured.

## Output schema

JSONL, one line per record. The first line is always a manifest.

```json
{"kind":"manifest","schema":1,"created":"2026-04-24T16:00:00Z","canary":"5f3a8c...","methods":["POST"],"types":["application/json", ...],"mismatch":false}
{"seq":0,"url":"https://...","method":"POST","content_type":"application/json","body_encoding":"json","variant":"application/json","status":200,"duration_ms":118,"response_len":421,"body_sha256":"...","header_sha256":"...","redirect_location":"","canary_reflected":false,"error_keyword":false,"body_truncated":false,"interesting":false,"error":"","response_headers":{"Server":"...","Vary":"..."}}
{"url":"https://...","method":"POST","kind":"summary","interesting":true,"score":65,"reason":"success status differs from authorization failure; response headers cluster by content-type family","statuses":{"application/json":200,"application/xml":403,"application/x-www-form-urlencoded":403},"header_groups":[{"hash":"...","content_types":["application/json"],"headers":{"X-Frame-Options":"DENY"}}, ...]}
```

Pass `--include-body` to add the (truncated to `--max-body-read`) response
body to each request record.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | Clean run, no interesting findings |
| 1 | Unexpected error (config, IO, network infrastructure) |
| 2 | CLI usage error (Go `flag` package default) |
| 3 | Scope violation — URLs outside `--scope-file` without `--allow-scope-drops` |
| 4 | Clean run, interesting findings present |

Agent pipelines should treat 3 as "stop, escalate to human" and 4 as
"trigger triage."

## Project layout

```
cmd/ctfuzz/           main, replay, report subcommands
internal/analyze/     signal scoring, structural clustering
internal/config/      flag parsing + validation
internal/fingerprint/ hashing + triage-header whitelist
internal/httpclient/  transport, retries, per-host rate limiter
internal/input/       URL and header loaders
internal/output/      atomic JSONL writer
internal/payload/     payload loader (depth caps, control-char guards)
internal/render/      body renderers + mismatch scenarios
internal/result/      record types (Request, Summary, Manifest)
internal/scope/       host allowlist matcher
```

See [DESIGN.md](./DESIGN.md) for the full architecture and threat model.

## Development

```sh
go test ./...
go test ./... -race
go vet ./...
go build -o ctfuzz ./cmd/ctfuzz
```

The `-race` suite should stay clean on every commit. All parser code is
covered by adversarial tests (`*_adversarial_test.go`).

## License

See [LICENSE](./LICENSE) once added. Until then, treat this as "all
rights reserved by the author." Drop in MIT/Apache-2.0/BSD-3-Clause as
you prefer before publishing.

## Author

[geeknik](https://github.com/geeknik) — info@geeknik-labs.com
