# Canonical Request Schema Notes
**Date:** 2026-06-10  
**Purpose:** Define what `CanonicalRequest` must look like to represent all datasets and the live Express `req` object (task 0.5).

---

## 1. Fields Present Across Datasets

| Field | data_capec | owasp_logs | modsec_learn | Payloads.csv | payload_full | XSS_dataset | cmd_injection | pt_wordlists | russellmitchell |
|-------|-----------|-----------|-------------|-------------|-------------|-------------|--------------|-------------|----------------|
| HTTP method | ✓ (GET/POST/etc) | ✓ | ✗ (implied GET) | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Full URL / request line | ✓ (`request_http_request`) | ✓ (from log line B) | ✗ | ✓ (full URL) | ✗ | ✗ | ✗ | ✗ | ✓ |
| Path | derivable | ✓ | ✗ | derivable | ✗ | ✗ | ✗ | ✓ | ✓ |
| Query string | derivable | ✓ | ✓ (is the payload) | derivable | ✗ | ✗ | ✗ | ✗ | ✓ |
| Request body | ✓ (`request_body`) | ✓ (some) | ✓ (some) | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| User-Agent | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Content-Type | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Other headers | ✓ (9 header columns) | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | partial |
| Raw payload (string) | derivable from path+query+body | derivable | ✓ (the record itself) | ✓ (full URL as string) | ✓ | ✓ | ✓ | ✓ | derivable |

---

## 2. Fields Present in data_capec (the richest dataset)

From `data_capec_multilabel.csv` columns:
```
request_http_method       → method
request_http_request      → path + query string (full request line, e.g. "/blog/index.php?id=1 UNION...")
request_http_protocol     → always HTTP/1.1 (ignore)
request_user_agent        → headers.user-agent
request_referer           → headers.referer (mostly NaN)
request_host              → headers.host
request_origin            → headers.origin (mostly NaN)
request_cookie            → headers.cookie (mostly NaN)
request_content_type      → headers.content-type (mostly NaN — GET requests)
request_accept            → headers.accept
request_accept_language   → headers.accept-language (mostly NaN)
request_accept_encoding   → headers.accept-encoding
request_do_not_track      → headers.dnt (mostly NaN)
request_connection        → headers.connection
request_body              → body (mostly NaN for GET)
```

Response fields `response_*` are **not available** at RASP intercept time — exclude from CanonicalRequest.

---

## 3. Unified Schema Recommendation

```typescript
interface CanonicalRequest {
  method: string;           // "GET", "POST", etc. — default "GET" if unknown
  path: string;             // URL path component (e.g. "/api/users"). Default "" if unavailable.
  query: string;            // Raw query string without "?" (e.g. "id=1 UNION SELECT..."). Default "".
  body: string;             // Request body as string. Default "".
  headers: {
    userAgent: string;      // Default "".
    contentType: string;    // Default "".
    referer: string;        // Default "".
    cookie: string;         // Default "".
    accept: string;         // Default "".
    host: string;           // Default "".
    // other headers not individually tracked but factored via unusual_headers_count
    raw: Record<string, string>;  // All headers as key-value for unusual_headers_count feature
  };
  rawPayload: string;       // Concatenation used as primary text for entropy/token/marker analysis.
                            // Construction: body || query || path (in this priority order)
                            // or just the raw string if dataset only provides a payload.
}
```

---

## 4. Field Availability by Dataset and Handling Strategy

| Dataset | method | path | query | body | headers | rawPayload | Strategy |
|---------|--------|------|-------|------|---------|------------|---------|
| data_capec | ✓ | parse from `request_http_request` | parse from `request_http_request` | `request_body` (NaN→"") | all 9 header cols | path + "?" + query | Parse request line: `GET /path?query HTTP/1.1` → split on space+`?` |
| owasp logs | parse section B | parse section B line | parse section B line | parse section B body | parse section B headers | path + "?" + query | Multi-section log parser needed |
| modsec_learn | ✗ (→"") | ✗ (→"") | the record IS the query | ✗ (→"") | ✗ (→ all empty) | the record | Wrap as `CanonicalRequest{query: record, rawPayload: record}` |
| Payloads.csv | ✗ (→"GET") | parse from full URL | parse from full URL | ✗ (→"") | ✗ (→ all empty) | full URL string | URL parse: extract path + query. Raw = full URL. |
| payload_full | ✗ (→"") | ✗ (→"") | ✗ (→"") | ✗ (→"") | ✗ (→ all empty) | the `payload` col | `rawPayload = payload`. All structural fields 0. |
| XSS_dataset | ✗ (→"") | ✗ (→"") | ✗ (→"") | ✗ (→"") | ✗ (→ all empty) | the `Sentence` col | `rawPayload = Sentence`. HTML snippets only. |
| cmd_injection | ✗ (→"") | ✗ (→"") | ✗ (→"") | ✗ (→"") | ✗ (→ all empty) | the `sentence` col | Decode HTML entities first, then `rawPayload = sentence`. |
| pt_wordlists | ✗ (→"GET") | the line IS the path | ✗ (→"") | ✗ (→"") | ✗ (→ all empty) | the line | `path = line`, `rawPayload = line`. |
| russellmitchell | ✓ (Apache log) | ✓ | ✓ | ✗ (→"") | partial | path + "?" + query | Apache CLF parser. Combine log + label files. |
| Express req (live) | ✓ | ✓ | ✓ | ✓ (if parsed) | ✓ (all) | body || query || path | Full context always available at middleware time. |

---

## 5. Known Schema Gaps and Resolutions

### Gap 1: rawPayload construction
Datasets give different things as "the attack content":
- Full URL (Payloads.csv) → the XSS is in the query parameter value
- Query string only (modsec_learn) → the SQLi is directly in query
- Raw HTML (XSS_dataset) → the XSS payload is the entire body
- Path only (pt_wordlists) → traversal is in the path

**Resolution:** `rawPayload` = the highest-signal text field available. Extractor features computed over `rawPayload` specifically. Structural features (path_depth, query_param_count, etc.) = 0 when path/query not available. This means structural features will be **systematically 0 for payload-only datasets** — this is a known limitation to document in the threats-to-validity section.

### Gap 2: No benign HTTP traffic with full structure
Benign samples mostly come from modsec_learn (query strings) and payloads_csv (URLs with benign paths). The OWASP honeypot has zero benign samples. russellmitchell benign rows have full structure but are a small set (3,435).

**Resolution:** Use modsec_learn legitimate (508,530 query strings) as the primary benign pool for IF training. Accept that benign structural feature distribution skews toward query-string-only context. Document as limitation.

### Gap 3: Response fields in data_capec
Columns `response_http_status_code`, `response_content_length`, etc. are present in the CSV and were used in the existing Python extractor (`status_code` feature). These are **unavailable at RASP intercept time**.

**Resolution:** Exclude `status_code` from `CanonicalRequest` and from the feature vector. The `status_code` column in the parquets must be dropped before training.

### Gap 4: Network-level fields
data_capec has `src_ip`, `src_port`, `dst_ip`, `dst_port`. These are network-layer data, not HTTP application-layer data. The TS extractor operates on the Express `req` object which does have `req.ip` / `req.socket.remoteAddress`, but IP-based features are out of scope (require cross-request state or threat intelligence feeds).

**Resolution:** Exclude IP fields from CanonicalRequest.

---

## 6. Final Proposed CanonicalRequest (for task 0.5)

```typescript
interface CanonicalRequest {
  method:       string;   // HTTP verb, uppercase. Default: ""
  path:         string;   // URL path, decoded. Default: ""
  query:        string;   // Raw query string (no leading "?"). Default: ""
  body:         string;   // Request body as UTF-8 string. Default: ""
  userAgent:    string;   // User-Agent header. Default: ""
  contentType:  string;   // Content-Type header. Default: ""
  referer:      string;   // Referer header. Default: ""
  cookie:       string;   // Cookie header. Default: ""
  extraHeaders: Record<string, string>; // All other request headers. Default: {}
}
// rawPayload is derived — not stored. Extractor computes it as:
// body !== "" ? body : query !== "" ? query : path
```

**Critical note:** The feature extractor derives `rawPayload` internally from the above fields. It must never be passed as a pre-computed string — that would duplicate logic and risk drift between datasets and production.
