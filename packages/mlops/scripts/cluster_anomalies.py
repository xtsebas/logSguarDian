#!/usr/bin/env python3
"""
Fase 3 of the CT/CI/CD pipeline — anomaly clustering over collected telemetry.

Loads the feature vectors accumulated by the MLOps collector (Fase 1/2),
scores each with the same if.onnx already used in production (via
onnxruntime, same input name/shape/output index as
packages/core/src/worker.ts), keeps the vectors IF flags as anomalous
(if_score < IF_THRESHOLD, same constant as packages/core/src/middleware.ts),
and groups them with DBSCAN so a human can review clusters instead of
individual events (Fase 4's `review-clusters` consumes this report).

Usage:
    python3 cluster_anomalies.py [--db PATH] [--if-model PATH] [--out PATH]
                                  [--eps FLOAT] [--min-samples INT]
"""
import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import onnxruntime as ort
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

SCRIPT_DIR = Path(__file__).resolve().parent
MLOPS_DIR = SCRIPT_DIR.parent
REPO_ROOT = MLOPS_DIR.parent.parent

DEFAULT_DB = MLOPS_DIR / "data" / "mlops-telemetry.db"
DEFAULT_IF_MODEL = REPO_ROOT / "training" / "models" / "if.onnx"
DEFAULT_OUT_DIR = MLOPS_DIR / "data"

# Same IF decision threshold as packages/core/src/middleware.ts (IF_THRESHOLD).
IF_THRESHOLD = 0.002486040118540811
IF_OUTPUT_IDX = 1

# Must match packages/extractor/src/index.ts FEATURE_NAMES exactly (order and
# count) — this is the single other place this 73-name list is duplicated,
# because the collector only stores raw float vectors, not feature names.
FEATURE_NAMES = [
    "payload_length", "payload_entropy", "uri_length", "path_length",
    "query_string_length", "body_length", "body_entropy",
    "path_depth", "query_param_count", "fragment_present",
    "special_char_ratio", "numeric_char_ratio", "uppercase_ratio",
    "whitespace_count", "newline_char_count", "null_byte_count",
    "extended_ascii_ratio", "payload_token_count",
    "url_encoded_ratio", "encoded_char_freq", "double_encoded_count",
    "hex_escape_count", "unicode_escape_count", "html_entity_count", "base64_like_count",
    "sqli_keyword_count", "sqli_keyword_density", "sqli_comment_count",
    "sqli_operator_count", "non_form_operator_count", "quote_count",
    "semicolon_count", "parenthesis_count", "union_present", "select_present",
    "xss_marker_count", "xss_marker_density", "html_tag_count",
    "script_tag_present", "js_event_handler_count", "javascript_url_count",
    "html_entity_density", "alert_function_present", "inline_style_present",
    "traversal_sequence_count", "path_separator_count", "absolute_path_indicator",
    "sensitive_file_target", "sensitive_extension_count", "file_extension_suspicious",
    "dotdot_encoded_count",
    "pipe_count", "backtick_count", "shell_command_count",
    "command_separator_count", "redirect_operator_count",
    "dollar_sign_count", "subshell_count", "os_path_indicator",
    "method_is_get", "method_is_post", "ua_present", "ua_length",
    "ua_suspicious", "content_type_encoded", "authorization_length",
    "unusual_headers_count", "status_code",
    "req_count_1s", "req_count_5s", "req_count_60s",
    "error_rate_4xx_60s", "endpoint_diversity_60s",
]
assert len(FEATURE_NAMES) == 73, f"expected 73 feature names, got {len(FEATURE_NAMES)}"

EXCLUDED_NAMES = {
    "status_code", "req_count_1s", "req_count_5s", "req_count_60s",
    "error_rate_4xx_60s", "endpoint_diversity_60s",
}
IF_ADDITIONAL_EXCLUDED = {
    "dotdot_encoded_count", "authorization_length", "unusual_headers_count",
    "null_byte_count", "os_path_indicator", "sensitive_file_target",
}
IF_MODEL_INDICES = [
    i for i, name in enumerate(FEATURE_NAMES)
    if name not in EXCLUDED_NAMES and name not in IF_ADDITIONAL_EXCLUDED
]
assert len(IF_MODEL_INDICES) == 61, f"expected 61 IF feature indices, got {len(IF_MODEL_INDICES)}"


def load_telemetry(db_path: Path) -> list[dict]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, source_id, predicted_class, confidence, vector, timestamp FROM telemetry_events ORDER BY id ASC"
    ).fetchall()
    conn.close()
    return [dict(r) | {"vector": json.loads(r["vector"])} for r in rows]


def score_anomalies(events: list[dict], if_model_path: Path) -> np.ndarray:
    session = ort.InferenceSession(str(if_model_path))
    vectors73 = np.array([e["vector"] for e in events], dtype=np.float32)
    if_input = vectors73[:, IF_MODEL_INDICES]
    output_name = session.get_outputs()[IF_OUTPUT_IDX].name
    result = session.run([output_name], {"float_input": if_input})[0]
    return np.asarray(result).reshape(-1)


def medoid(vectors: np.ndarray) -> np.ndarray:
    """Point in the cluster with the smallest total distance to all others."""
    if len(vectors) == 1:
        return vectors[0]
    dists = np.linalg.norm(vectors[:, None, :] - vectors[None, :, :], axis=2).sum(axis=1)
    return vectors[int(np.argmin(dists))]


def cluster_report(events: list[dict], if_scores: np.ndarray, eps: float, min_samples: int) -> dict:
    is_anomaly = if_scores < IF_THRESHOLD
    anomalous = [e for e, a in zip(events, is_anomaly) if a]
    anomalous_scores = if_scores[is_anomaly]

    if not anomalous:
        return {"total_events": len(events), "anomalous_events": 0, "clusters": []}

    vectors = np.array([e["vector"] for e in anomalous], dtype=np.float32)[:, IF_MODEL_INDICES]
    scaled = StandardScaler().fit_transform(vectors)

    labels = DBSCAN(eps=eps, min_samples=min_samples).fit_predict(scaled)

    clusters = []
    for label in sorted(set(labels)):
        member_idx = [i for i, l in enumerate(labels) if l == label]
        members = [anomalous[i] for i in member_idx]
        member_vectors = vectors[member_idx]
        rep = medoid(member_vectors)

        source_counts: dict[str, int] = {}
        class_counts: dict[str, int] = {}
        for m in members:
            source_counts[m["source_id"]] = source_counts.get(m["source_id"], 0) + 1
            class_counts[m["predicted_class"]] = class_counts.get(m["predicted_class"], 0) + 1

        clusters.append({
            "cluster_id": "noise" if label == -1 else int(label),
            "size": len(members),
            "avg_if_score": float(np.mean(anomalous_scores[member_idx])),
            "sources": source_counts,
            "predicted_classes": class_counts,
            "representative_vector": rep.tolist(),
            "member_event_ids": [m["id"] for m in members],
        })

    clusters.sort(key=lambda c: c["size"], reverse=True)
    return {
        "total_events": len(events),
        "anomalous_events": len(anomalous),
        "eps": eps,
        "min_samples": min_samples,
        "clusters": clusters,
    }


def print_summary(report: dict) -> None:
    print(f"Total telemetry events: {report['total_events']}")
    print(f"Anomalous (if_score < {IF_THRESHOLD}): {report['anomalous_events']}")
    if not report["clusters"]:
        print("No anomaly clusters found.")
        return
    print(f"\nClusters (eps={report['eps']}, min_samples={report['min_samples']}):")
    print(f"{'cluster':<10}{'size':<8}{'avg_if_score':<16}{'sources':<40}predicted_classes")
    for c in report["clusters"]:
        sources = ", ".join(f"{k}:{v}" for k, v in c["sources"].items())
        classes = ", ".join(f"{k}:{v}" for k, v in c["predicted_classes"].items())
        print(f"{str(c['cluster_id']):<10}{c['size']:<8}{c['avg_if_score']:<16.6f}{sources:<40}{classes}")

        if any(src.startswith("sim-host-novel") for src in c["sources"]):
            print(f"  -> cluster {c['cluster_id']} is (partly) the deliberately injected novel technique — "
                  f"detected as anomalous without being labeled.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--if-model", type=Path, default=DEFAULT_IF_MODEL)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--eps", type=float, default=2.5)
    parser.add_argument("--min-samples", type=int, default=3)
    args = parser.parse_args()

    if not args.db.exists():
        print(f"error: telemetry db not found at {args.db} — run simulate-fleet.ts first", file=sys.stderr)
        sys.exit(1)
    if not args.if_model.exists():
        print(f"error: if.onnx not found at {args.if_model}", file=sys.stderr)
        sys.exit(1)

    events = load_telemetry(args.db)
    if not events:
        print("error: telemetry db has no events", file=sys.stderr)
        sys.exit(1)

    if_scores = score_anomalies(events, args.if_model)
    report = cluster_report(events, if_scores, args.eps, args.min_samples)
    print_summary(report)

    out_path = args.out or (DEFAULT_OUT_DIR / f"cluster_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2))
    print(f"\nReport written to {out_path}")


if __name__ == "__main__":
    main()
