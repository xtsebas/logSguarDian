# Config 1/2/3 Evaluation Documentation

Copied from the `logSguarDian-vulnerable-project` repository (the deliberately
vulnerable Express app used to evaluate logSguarDian in Config 1/2/3a/3b).
Preserved here for thesis consolidation - source of truth for ongoing changes
remains the vulnerable-app repo.

Source branch: `feat/config3-waf-plus-logsguardian` (not present on that
repo's default branch at copy time).

Contents:
- `config2-results.md` / `config2-latency-evaluation.md` — Config 2
  (logSguarDian only): coverage, latency investigation, OBJ.3 criterion
  analysis
- `config3-waf-plan.md` — Config 3 planning notes (WAF-only and layered
  setup)
- `config3b-results.md` — Config 3a/3b (WAF-only and layered): the
  590-payload defense-in-depth comparison, the multipart/stored-XSS bug
  found and fixed, User-Agent sensitivity finding
