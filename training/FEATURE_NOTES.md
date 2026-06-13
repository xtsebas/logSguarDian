# Feature Vector Notes
**Date:** 2026-06-11  

---

## Extractor output: 72 features

`packages/extractor/src/index.ts` produces a vector of 72 named features (see `FEATURE_NAMES`).

---

## Features excluded from training (6 columns dropped)

The following 6 features are **excluded before training** and must not appear in any model's input.

| Feature | Reason |
|---------|--------|
| `status_code` | HTTP response field — unavailable at RASP middleware intercept time (the response does not exist when the request arrives) |
| `req_count_1s` | Requires cross-request state (request rate over a sliding window). Not available as a per-request feature. |
| `req_count_5s` | Same as above. |
| `req_count_60s` | Same as above. |
| `error_rate_4xx_60s` | Requires aggregated response codes over a time window. Both response data and cross-request state are unavailable at intercept time. |
| `endpoint_diversity_60s` | Requires cross-request state (distinct endpoints seen over a time window). |

These 6 features always output 0 in the extractor (see `TEMPORAL_FEATURES` in `index.ts`). Training on zero-variance features wastes model capacity and produces an incorrect feature contract — the ONNX model's `n_features` would be 72 but the worker_thread in production would supply 66 non-zero values.

**Model input dimension: 66**

---

## Drop procedure

After running the TS extractor CLI and before training, drop these columns:

```python
FEATURES_TO_DROP = [
    "status_code",
    "req_count_1s",
    "req_count_5s",
    "req_count_60s",
    "error_rate_4xx_60s",
    "endpoint_diversity_60s",
]
df = df.drop(columns=FEATURES_TO_DROP, errors="ignore")
```

The `parity_report.json` written by notebook 05 must include `"n_features": 66`.

---

## Feature groups retained (66 total)

| Group | Count | Features |
|-------|-------|---------|
| 1 — Lengths | 10 | payload_length, payload_entropy, uri_length, path_length, query_string_length, body_length, body_entropy, path_depth, query_param_count, fragment_present |
| 2 — Composition | 8 | special_char_ratio, numeric_char_ratio, uppercase_ratio, whitespace_count, newline_char_count, null_byte_count, extended_ascii_ratio, payload_token_count |
| 3 — Encoding | 7 | url_encoded_ratio, encoded_char_freq, double_encoded_count, hex_escape_count, unicode_escape_count, html_entity_count, base64_like_count |
| 4 — SQLi | 9 | sqli_keyword_count, sqli_keyword_density, sqli_comment_count, sqli_operator_count, quote_count, semicolon_count, parenthesis_count, union_present, select_present |
| 5 — XSS | 9 | xss_marker_count, xss_marker_density, html_tag_count, script_tag_present, js_event_handler_count, javascript_url_count, html_entity_density, alert_function_present, inline_style_present |
| 6 — Path Traversal | 7 | traversal_sequence_count, path_separator_count, absolute_path_indicator, sensitive_file_target, sensitive_extension_count, file_extension_suspicious, dotdot_encoded_count |
| 7 — Command Injection | 8 | pipe_count, backtick_count, shell_command_count, command_separator_count, redirect_operator_count, dollar_sign_count, subshell_count, os_path_indicator |
| 8 — HTTP Request | 8 | method_is_get, method_is_post, ua_present, ua_length, ua_suspicious, content_type_encoded, authorization_length, unusual_headers_count |
| **Total** | **66** | |
