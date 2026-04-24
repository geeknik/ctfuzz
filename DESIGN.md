# DESIGN.md — `ctfuzz`

## 1. Purpose

`ctfuzz` is a single-use HTTP content-type fuzzing tool for discovering routes and API endpoints that behave differently depending on the submitted `Content-Type` header and body encoding.

Many web applications route, validate, parse, authenticate, or authorize requests differently based on content type. A route that rejects JSON may accept form data. An endpoint that validates XML poorly may expose parser bugs, deserialization paths, XXE-adjacent behavior, or inconsistent authorization logic. `ctfuzz` makes those inconsistencies visible.

The tool takes a list of target URLs and sends semantically equivalent payloads using multiple content types:

* `application/json`
* `application/xml`
* `application/x-www-form-urlencoded`

It records status codes, response sizes, response hashes, timing, redirects, selected headers, and body fingerprints so the operator can quickly identify anomalous behavior.

---

## 2. Non-Goals

`ctfuzz` is not:

* A general-purpose web fuzzer
* A crawler
* A vulnerability scanner
* A WAF bypass framework
* A blind SSRF or XXE exploit tool
* A destructive load-testing tool
* A recursive parameter discovery engine

Version 1 focuses only on **known URLs** and **content-type differential behavior**.

---

## 3. Threat Model / Research Use Case

Authorized security testing often misses content-type-specific behavior because testers replay one request shape repeatedly.

Common failure modes:

* JSON endpoint accepts form data unexpectedly
* Form endpoint accepts JSON with looser validation
* XML route invokes a different parser path
* Middleware authentication applies only to one content type
* Request body parser disagreement causes parameter smuggling
* API gateway validates JSON, but backend accepts form data
* Different content types trigger different framework handlers
* Error messages disclose parser, framework, schema, or stack details

`ctfuzz` highlights these cases by comparing how the same logical payload behaves across encodings.

---

## 4. Core Principle

For every target URL, send equivalent payload intent through multiple body encodings.

Example logical payload:

```json
{
  "id": "1",
  "name": "ctfuzz",
  "admin": "false"
}
```

Encoded as JSON:

```http
Content-Type: application/json

{"id":"1","name":"ctfuzz","admin":"false"}
```

Encoded as XML:

```http
Content-Type: application/xml

<root><id>1</id><name>ctfuzz</name><admin>false</admin></root>
```

Encoded as form data:

```http
Content-Type: application/x-www-form-urlencoded

id=1&name=ctfuzz&admin=false
```

The value is not in one request. The value is in the **delta**.

---

## 5. CLI Interface

```bash
ctfuzz \
  --urls urls.txt \
  --method POST \
  --payload payload.json \
  --headers headers.txt \
  --out results.jsonl \
  --concurrency 10 \
  --timeout 8s
```

### Required Arguments

| Argument    | Description                               |
| ----------- | ----------------------------------------- |
| `--urls`    | File containing one URL per line          |
| `--payload` | Base payload file, preferably JSON object |

### Optional Arguments

| Argument             |                Default | Description                        |
| -------------------- | ---------------------: | ---------------------------------- |
| `--method`           |                 `POST` | HTTP method to use                 |
| `--headers`          |                   none | Static headers to include          |
| `--out`              | `ctfuzz-results.jsonl` | Output file                        |
| `--concurrency`      |                    `8` | Parallel workers                   |
| `--timeout`          |                  `10s` | Per-request timeout                |
| `--delay`            |                  `0ms` | Delay between requests per worker  |
| `--proxy`            |                   none | HTTP/SOCKS proxy URL               |
| `--insecure`         |                  false | Skip TLS verification              |
| `--follow-redirects` |                  false | Follow redirects                   |
| `--max-body-read`    |                `65536` | Max response bytes to fingerprint  |
| `--include-body`     |                  false | Store truncated response bodies    |
| `--types`            |                    all | Comma-separated content types      |
| `--canary`           |                 random | Canary value inserted into payload |

---

## 6. Input Files

### 6.1 URL List

```txt
https://example.com/api/user
https://example.com/api/search
https://example.com/login
https://example.com/admin/action
```

Blank lines and lines beginning with `#` are ignored.

### 6.2 Payload File

The v1 payload format is JSON.

```json
{
  "username": "ctfuzz_user",
  "password": "ctfuzz_pass",
  "id": "1",
  "role": "user",
  "debug": "false"
}
```

The payload is treated as a logical key-value structure and rendered into each supported content type.

### 6.3 Headers File

```txt
Authorization: Bearer REDACTED
Cookie: session=REDACTED
User-Agent: ctfuzz/0.1
Accept: */*
```

`Content-Type` is controlled by `ctfuzz` and should not be supplied manually unless `--force-content-type` is explicitly implemented later.

---

## 7. Content-Type Renderers

### 7.1 JSON Renderer

Input object is serialized compactly.

```http
Content-Type: application/json
```

Body:

```json
{"username":"ctfuzz_user","password":"ctfuzz_pass","id":"1"}
```

### 7.2 XML Renderer

Input object is wrapped in a configurable root node.

```http
Content-Type: application/xml
```

Body:

```xml
<root>
  <username>ctfuzz_user</username>
  <password>ctfuzz_pass</password>
  <id>1</id>
</root>
```

XML output must escape special characters safely.

Default root node: `root`

Optional future flag:

```bash
--xml-root request
```

### 7.3 Form Renderer

Input object is encoded as URL-encoded form data.

```http
Content-Type: application/x-www-form-urlencoded
```

Body:

```txt
username=ctfuzz_user&password=ctfuzz_pass&id=1
```

Nested objects are flattened using dotted keys in v1:

```json
{
  "user": {
    "name": "alice"
  }
}
```

Becomes:

```txt
user.name=alice
```

---

## 8. Request Matrix

For each URL, generate a request matrix:

| URL    | Method | Content-Type                        | Body Renderer |
| ------ | ------ | ----------------------------------- | ------------- |
| target | POST   | `application/json`                  | JSON          |
| target | POST   | `application/xml`                   | XML           |
| target | POST   | `application/x-www-form-urlencoded` | Form          |

Optional v1.1 additions:

* `text/plain` with JSON body
* Missing `Content-Type`
* Incorrect `Content-Type` with mismatched body
* `application/json; charset=utf-8`
* `application/xml; charset=utf-8`
* Duplicate `Content-Type` header handling, if the HTTP client permits it

---

## 9. Differential Detection

`ctfuzz` does not need to declare a vulnerability. It needs to surface interesting differences.

For each URL, compare responses across content types using:

* Status code
* Response body length
* Response SHA-256 hash
* SimHash or fuzzy body hash, optional
* Header set differences
* Redirect location
* Response time
* Error keywords
* Reflected canary presence
* Authentication/authorization indicators

### Interesting Signals

A URL is marked `interesting` when one or more of these are true:

* One content type returns `2xx` while others return `4xx` or `5xx`
* One content type returns `401/403` while another returns `200/204/302`
* One content type produces a materially larger response
* One content type exposes a stack trace or parser error
* One content type reflects the canary and others do not
* One content type redirects to a privileged or unexpected path
* XML returns errors mentioning parser internals
* Form data triggers different validation behavior than JSON
* Same parameters produce different authorization outcomes

---

## 10. Result Schema

Output is JSON Lines.

One line per request:

```json
{
  "url": "https://example.com/api/user",
  "method": "POST",
  "content_type": "application/json",
  "status": 400,
  "duration_ms": 118,
  "response_len": 421,
  "body_sha256": "...",
  "header_sha256": "...",
  "redirect_location": "",
  "canary_reflected": false,
  "interesting": false,
  "error": ""
}
```

Optional grouped summary line:

```json
{
  "url": "https://example.com/api/user",
  "kind": "summary",
  "interesting": true,
  "reason": "application/x-www-form-urlencoded returned 200 while JSON/XML returned 403",
  "statuses": {
    "application/json": 403,
    "application/xml": 403,
    "application/x-www-form-urlencoded": 200
  }
}
```

---

## 11. Console Output

Default console output should be sparse and operator-friendly.

```txt
[+] loaded 124 urls
[+] loaded payload with 5 keys
[+] testing 3 content-types per URL
[!] interesting https://example.com/api/user form=200 json=403 xml=403
[!] interesting https://example.com/login xml=500 json=401 form=401
[+] wrote results to ctfuzz-results.jsonl
```

Verbose mode may print every request.

```bash
--verbose
```

---

## 12. Safety Controls

`ctfuzz` should be boringly safe by default.

Defaults:

* No crawling
* No recursion
* No automatic exploit payloads
* No XXE payloads by default
* No destructive methods by default
* No request body above a conservative size
* No retry storm
* No redirect following unless enabled
* Bounded concurrency
* Per-host rate limiting optional

Recommended default limits:

| Control           |  Default |
| ----------------- | -------: |
| Max concurrency   |      `8` |
| Timeout           |    `10s` |
| Max response read | `64 KiB` |
| Max request body  | `64 KiB` |
| Retries           |      `0` |
| Redirects         | disabled |

---

## 13. Architecture

```txt
                 ┌──────────────┐
                 │  CLI Config  │
                 └──────┬───────┘
                        │
       ┌────────────────┼────────────────┐
       │                │                │
┌──────▼──────┐ ┌───────▼──────┐ ┌───────▼──────┐
│ URL Loader  │ │ Header Loader │ │ Payload Loader│
└──────┬──────┘ └───────┬──────┘ └───────┬──────┘
       │                │                │
       └────────────────┼────────────────┘
                        │
              ┌─────────▼─────────┐
              │ Request Generator │
              └─────────┬─────────┘
                        │
              ┌─────────▼─────────┐
              │   Worker Pool     │
              └─────────┬─────────┘
                        │
              ┌─────────▼─────────┐
              │ Response Analyzer │
              └─────────┬─────────┘
                        │
              ┌─────────▼─────────┐
              │ Result Writer     │
              └───────────────────┘
```

---

## 14. Internal Modules

### Go Package Layout

```txt
cmd/ctfuzz/main.go
internal/config/config.go
internal/input/urls.go
internal/input/headers.go
internal/payload/payload.go
internal/render/json.go
internal/render/xml.go
internal/render/form.go
internal/httpclient/client.go
internal/fingerprint/fingerprint.go
internal/analyze/analyze.go
internal/output/jsonl.go
```

### Rust Crate Layout

```txt
src/main.rs
src/config.rs
src/input.rs
src/payload.rs
src/render/json.rs
src/render/xml.rs
src/render/form.rs
src/client.rs
src/fingerprint.rs
src/analyze.rs
src/output.rs
```

---

## 15. Go vs Rust Recommendation

### Go

Best fit if the priority is fast implementation, simple static binaries, and straightforward HTTP concurrency.

Recommended Go stack:

* `net/http`
* `context`
* `encoding/json`
* `encoding/xml`
* `net/url`
* `crypto/sha256`
* `cobra` or stdlib `flag`
* `errgroup`, optional

### Rust

Best fit if the priority is stronger typing, safer parsing, and cleaner long-term extension.

Recommended Rust stack:

* `reqwest`
* `tokio`
* `serde`
* `serde_json`
* `quick-xml`
* `clap`
* `sha2`
* `urlencoding`
* `tracing`

### Recommendation

Use **Go** for v1.

Reason: this is a single-use operator tool. Go provides excellent HTTP ergonomics, easy cross-compilation, fast build times, and a small dependency surface.

---

## 16. Implementation Notes

### Request Handling

Each request should have its own context with timeout.

Do not reuse request bodies across retries. Generate fresh body readers per request.

### Header Handling

Static headers are applied first. `Content-Type` is applied last to prevent accidental override.

Recommended default headers:

```http
User-Agent: ctfuzz/0.1
Accept: */*
```

### TLS

TLS verification is enabled by default.

`--insecure` should be visually obvious in logs:

```txt
[!] TLS certificate verification disabled
```

### Proxy Support

Support standard proxy URLs:

```bash
--proxy http://127.0.0.1:8080
--proxy socks5://127.0.0.1:9050
```

This allows easy Burp/ZAP inspection.

---

## 17. Canary Strategy

Generate one random canary per run:

```txt
ctfuzz_8f3a91c2
```

Optionally inject it into payload values:

```json
{
  "username": "ctfuzz_8f3a91c2",
  "search": "ctfuzz_8f3a91c2"
}
```

The response analyzer checks whether the canary appears in the response body.

Canary reflection is useful for identifying parsing success, template reflection, and alternate processing paths.

---

## 18. Interestingness Scoring

Each URL receives a score from 0 to 100.

Suggested scoring:

| Signal                                 | Points |
| -------------------------------------- | -----: |
| Mixed auth result, e.g. `403` vs `200` |    +40 |
| `5xx` only for one content type        |    +25 |
| Canary reflected only for one type     |    +20 |
| Response size differs by >50%          |    +10 |
| Redirect differs                       |    +10 |
| Parser/framework error keyword         |    +15 |
| Response time differs by >3x           |     +5 |

Example summary:

```json
{
  "url": "https://example.com/api/user",
  "score": 75,
  "reason": "form returned 200 while json/xml returned 403; canary reflected in form response"
}
```

---

## 19. Error Keyword Detection

Flag responses containing terms like:

```txt
stack trace
traceback
exception
parse error
unexpected token
invalid character
xml parser
SAXParseException
JsonParseException
NullPointerException
TypeError
ValueError
panic
fatal error
```

This should be a signal, not a verdict.

---

## 20. Testing Plan

### Unit Tests

* URL loader ignores comments and blanks
* Header parser handles duplicate-like input safely
* JSON renderer emits valid JSON
* XML renderer escapes special characters
* Form renderer URL-encodes correctly
* Nested object flattening works
* SHA-256 fingerprinting is stable
* Interestingness scoring detects status deltas

### Integration Tests

Spin up a local test server with routes that intentionally behave differently:

| Route          |      JSON |    XML |      Form |
| -------------- | --------: | -----: | --------: |
| `/same`        |       200 |    200 |       200 |
| `/json-only`   |       200 |    415 |       415 |
| `/form-bypass` |       403 |    403 |       200 |
| `/xml-error`   |       401 |    500 |       401 |
| `/reflect`     | no canary | canary | no canary |

Expected: only differential routes are marked interesting.

---

## 21. MVP Acceptance Criteria

The MVP is complete when:

* Accepts URL list
* Accepts JSON payload
* Renders JSON, XML, and form bodies
* Sends requests with correct `Content-Type`
* Supports static headers
* Supports concurrency
* Enforces timeout
* Writes JSONL results
* Groups responses by URL
* Flags differential behavior
* Runs as a single static-ish binary

---

## 22. Example Run

```bash
ctfuzz \
  --urls urls.txt \
  --payload payload.json \
  --headers auth.txt \
  --out out.jsonl \
  --concurrency 5 \
  --proxy http://127.0.0.1:8080
```

Example finding:

```txt
[!] interesting https://target.local/api/profile score=80
    json: 403 len=91 hash=3d2a...
    xml:  403 len=91 hash=3d2a...
    form: 200 len=1842 hash=a81f...
    reason: form returned success where json/xml returned forbidden
```

---

## 23. Future Enhancements

Useful but not needed for v1:

* Mismatched body/content-type mode
* Multipart form-data renderer
* Per-route method matrix: `POST`, `PUT`, `PATCH`
* Raw request template input
* HAR import
* OpenAPI import
* Burp sitemap import
* Baseline GET comparison
* Fuzzy body hashing
* HTML title extraction
* JSON key extraction from responses
* Automatic replay command generation
* Markdown/HTML report output
* Header mutation: `Accept`, `X-HTTP-Method-Override`
* Charset variants
* Vendor JSON types like `application/vnd.api+json`
* GraphQL-specific mode

---

## 24. Design Bias

`ctfuzz` should be:

* Small
* Fast
* Auditable
* Easy to run through Burp
* Conservative by default
* Loud only when something differs
* Dumb enough to trust
* Sharp enough to find weird parser edges

The point is not to prove exploitation. The point is to show the operator where the application stops behaving consistently.
