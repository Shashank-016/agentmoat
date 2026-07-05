# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-07-05

### Added
- **Public-dataset benchmark suite:** one-command `python benchmarks/run.py` measuring the
  argument firewall against AgentDojo and the injection-text detector against
  `deepset/prompt-injections`, with machine-readable `benchmarks/results/latest.json`.
- **Overhead micro-benchmark:** `benchmarks/overhead.py` reporting injection-scan,
  argument-constraint, and end-to-end MCP-proxy per-call latency, summarized in the README.
- **Per-language breakdown** of injection-text catch rate and FPR (English vs. non-English,
  and per-language, via `langdetect`), exposing that the English-only regexes score 8.9% on
  English attacks and 0.0% on the non-English portion of the corpus.
- **Uncaught-case analysis** in the firewall scenario: every case that slips through is written
  to `benchmarks/results/uncaught_cases.json` with the tool(s) reused and a reason, plus a
  by-category summary folded into `latest.json` and printed in the run output.
- **`benchmarks` install extra** (`pip install "agentmoat[benchmarks]"`) declaring the
  benchmark-only dependencies (`datasets`, `agentdojo`, `langdetect`) with pinned ranges.
- **OWASP Top 10 for Agentic Applications (2026) mapping** in the README and
  `docs/owasp-mapping.md`.
- **Documentation:** README sections for secret/PII redaction, a "How AgentMoat compares"
  comparison against other agent-guardrail projects, and measured performance overhead.

### Changed
- **README now leads with deterministic tool-boundary enforcement** as the security boundary,
  with regex/embedding injection detection presented as a bypassable defense-in-depth signal.
- **README benchmark section rewritten** around the measured numbers with honest framing —
  the firewall result is an offline replay "evaluated against AgentDojo attack cases" (not a
  live-agent benchmark), and its 0% FPR is favorable by construction (the least-privilege
  policy is derived from the same task suite).
- **Packaging metadata:** enforcement-first project description, real maintainer name, and the
  version bumped to 0.1.1 across `pyproject.toml`, `agentmoat.__version__`, and the API app.

### Security
- **Kill-switch `/control` routes are gated by `AGENTMOAT_API_KEY`** like the rest of the audit
  API, with regression tests asserting every mutating endpoint (`kill`, `kill-all`, `revive`)
  rejects unauthenticated callers.

### Fixed
- **Benchmark embeddings attribution:** the injection-text scenario reported the embeddings pass
  as a union count byte-identical to the rule-based block, so the embedding pass got no
  independent credit. It now attributes catches to rules-only / embeddings-only / both and
  records the maximum attack similarity observed, making a zero contribution verifiable
  (measured: 0 added catches, max similarity 0.629 vs. the 0.82 threshold).
- **Benchmark firewall attribution:** policy vs. argument-constraint catches are now reported as
  disjoint buckets (policy-only / constraint-only / both) instead of overlapping counts, so a
  case tripping both is no longer credited to policy alone.
- `EventBus.__bool__` always returns `True`, so an empty bus is never mistaken for absent
  (falsy-when-empty footgun).

## [0.1.0] - 2026-06-10

### Added
- **Core instrumentation:** `GuardedClient` / `AsyncGuardedClient` (drop-in wrappers for the
  Anthropic SDK, sync + async + streaming), `AgentMoatCallback` for LangGraph, and a unified
  `SecurityEvent` bus with SQLite store and hash-chained JSONL audit logging.
- **Detection engine:** prompt-injection detector (regex + optional embeddings), tool-policy
  engine (allow/deny + rate limits), and a cross-agent trust scorer.
- **MCP transparent proxy:** stdio and SSE proxy that intercepts and enforces on any
  MCP-compatible tool server with no agent code changes.
- **Argument-level tool constraints:** path-traversal, SSRF, shell-metacharacter, and
  sensitive-path detection, plus configurable per-tool path/URL allow- and deny-lists.
- **Tamper-evident audit log:** SHA-256 hash chaining with `agentmoat audit verify`.
- **Response controls:** `observe` / `enforce` / `interactive` modes, human-in-the-loop approval
  gate, and a process-wide kill switch (with HTTP control endpoints).
- **OpenAI SDK support:** `GuardedOpenAI` / `AsyncGuardedOpenAI` reusing the same engine.
- **Audit API + dashboard:** FastAPI service (authenticated) and a React event/timeline UI.

### Security / hardening
- Reliable event persistence in sync and async contexts (background persistence worker).
- Fail-closed on internal engine errors in enforce/interactive mode; fail-open-but-logged in
  observe mode.
- API-key authentication on the audit API.
- Subprocess stderr draining in the MCP stdio client (deadlock fix).
- Bounded, TTL/LRU in-memory state for trust and rate-limit data.
- Secret/PII redaction before persistence.
- Timezone-aware timestamps throughout.

[Unreleased]: https://github.com/Shashank-016/agentmoat/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/Shashank-016/agentmoat/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Shashank-016/agentmoat/releases/tag/v0.1.0
