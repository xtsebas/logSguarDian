/**
 * attack-signal-score.ts
 *
 * Shared attack-signal scoring used by both:
 * - body-parser.ts (extractBestPayload) for multi-field bodies
 * - index.ts (deriveRawPayload) for body/query/path selection
 *
 * Both call sites need the exact same formula — previously duplicated
 * inline in extractBestPayload, risking drift. This is the single source
 * of truth.
 */
import {
  computeXssFeatures,
  computeSqliFeatures,
  computeCommandInjectionFeatures,
  computePathTraversalFeatures,
} from "./semantic";
import { safeDecodeURIComponent } from "./normalizers";

export function scoreAttackSignal(s: string): number {
  if (!s || s.length < 2) return 0;

  const xss = computeXssFeatures(s);
  const sqli = computeSqliFeatures(s);
  const cmdi = computeCommandInjectionFeatures(s);
  const pt = computePathTraversalFeatures(s);

  return (
    (xss.xss_marker_count || 0) +
    (xss.script_tag_present || 0) * 2 +
    (xss.js_event_handler_count || 0) +
    (xss.alert_function_present || 0) +
    (sqli.sqli_keyword_count || 0) +
    (sqli.sqli_operator_count || 0) +
    (sqli.union_present || 0) * 2 +
    (cmdi.shell_command_count || 0) +
    (cmdi.command_separator_count || 0) +
    (cmdi.subshell_count || 0) +
    (pt.traversal_sequence_count || 0) * 2 +
    (pt.dotdot_encoded_count || 0) +
    // absolute_path_indicator deliberately excluded: it fires on any
    // string starting with '/', which is true of virtually every HTTP
    // path — as a scoring term it adds constant noise rather than
    // discriminating signal (verified: caused a bare "/p" to outscore
    // genuine candidates purely from its leading slash).
    (pt.sensitive_file_target || 0) * 2
  );
}

/**
 * Like scoreAttackSignal, but also considers the percent-decoded form of
 * `s` and takes the higher of the two scores. SQLi/CMDI/path-traversal
 * feature computation deliberately reads raw (undecoded) text downstream
 * — see computeXssFeatures's scope note in semantic.ts — but for
 * body/query/path *candidate selection* specifically, scoring only the
 * raw form misses attacks whose signal is entirely hidden behind
 * percent-encoding (e.g. `chr%28122%29...` never matches any keyword
 * pattern, while its decoded form `chr(122)...` does). Used only by
 * deriveRawPayload's candidate comparison — the winning candidate is
 * still returned in its original, undecoded form.
 */
export function scoreAttackSignalWithDecoding(s: string): number {
  const rawScore = scoreAttackSignal(s);
  const decoded = safeDecodeURIComponent(s);
  if (decoded === s) return rawScore;
  return Math.max(rawScore, scoreAttackSignal(decoded));
}
