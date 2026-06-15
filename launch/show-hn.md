# Show HN draft

> Status: DRAFT — for review, not posted. No links submitted anywhere.

## Title (pick one, ≤80 chars)

- `Show HN: AgentMoat – an enforcement layer that firewalls AI agent tool calls`
- `Show HN: AgentMoat – block dangerous agent tool calls before they run (MIT)`

## URL

https://github.com/Shashank-016/agentmoat

## Post body

Most "AI agent security" tools try to *detect* prompt injection in the text going
into the model. That's useful, but it's a probabilistic heuristic attackers
paraphrase around — and by the time a bad instruction has been recognized, the
agent may already be calling `write_file("/etc/crontab", ...)` or POSTing your
data somewhere.

AgentMoat starts from the other end: the **action**. It sits between the model's
decision and the tool that executes it, and enforces a policy on the *actual
arguments* of every tool call before it runs:

- **Argument-level tool firewall** — per-agent allow/deny tool lists plus
  always-on detectors for path traversal, SSRF targets (cloud metadata IP,
  loopback, RFC-1918), shell metacharacters, and sensitive paths
  (`/etc`, `~/.ssh`, `.env`). `write_file` being allowed doesn't mean
  `write_file("/etc/shadow")` is.
- **Tamper-evident audit log** — every decision in a SHA-256 hash-chained JSONL
  file you can verify line-by-line (`agentmoat audit verify`).
- **Trust provenance** — a session's trust score degrades as it ingests external
  content and is inherited across agent handoffs.
- **Kill switch** — halt one session or every session in the process, in code or
  over HTTP.

Prompt-injection detection is *in* the box, but deliberately demoted to a
defense-in-depth heuristic. The controls that block an action don't depend on
recognizing the prompt that tried to cause it.

It's a one-line drop-in across the Anthropic & OpenAI SDKs and LangGraph, and a
transparent stdio/SSE proxy for any MCP tool server (no agent code change at all).

### I benchmarked it against public datasets and I'm posting the unflattering numbers too

One command (`python benchmarks/run.py`), two surfaces reported separately:

**Argument firewall vs. AgentDojo (609 indirect-injection cases):**
86.0% caught (524/609), 0.0% false positives on 339 benign tool calls, ~0.10ms
per-call overhead. But here's the honest part: *all* 524 catches come from
least-privilege tool policy (the attack needs a tool the benign task never used);
my argument-level constraints catch **0** of them, because AgentDojo's attacks are
financial/messaging exfiltration, not the filesystem/SSRF class those detectors
target. The benchmark publishes that decomposition and the exact derived policy.

**Injection-text detector vs. deepset/prompt-injections:** 5.3% caught (14/263),
0 false positives. The opt-in embedding model added *zero* extra catches on this
set while costing ~200× the latency. That's a weak number, and it's exactly why I
don't lead with injection detection.

I also mapped every control to the new OWASP Top 10 for Agentic Applications
(Dec 2025): 1 fully covered (tool misuse), 8 partial, 1 out of scope
(supply chain). The mapping says "partial" and "out of scope" out loud.

MIT, alpha, no telemetry. It will not catch a semantically-valid-but-malicious
call through an allowed tool, and it's single-process today (multi-process kill
switch needs a shared store — on the roadmap). Happy to be told where the model
is wrong.

## Likely HN questions — prepared answers

**"Isn't this just least-privilege / OPA for tools?"** The policy layer is
least-privilege, yes, and the benchmark is honest that least-privilege does most
of the AgentDojo work. The differentiators are (a) argument-level inspection on
top of name-level allow/deny, (b) the hash-chained audit trail, and (c) it speaks
MCP and the Anthropic/OpenAI SDKs as a true drop-in, so you get it without
re-plumbing your agent.

**"86% but constraints caught 0 — isn't the headline misleading?"** That's why
the decomposition is in the README and the JSON, not buried. The 86% is a real,
reproducible property of least-privilege on that dataset; I refuse to pass it off
as argument inspection.

**"Why is injection detection so bad (5.3%)?"** deepset is diverse/multilingual
and the regex set targets known English patterns. It's defense-in-depth, not the
moat. Improving it is a good-first-issue.

**"Does it add latency to my agent?"** ~0.10ms of engine work per intercepted
call (rule-based), which is noise next to the LLM round-trip. Embeddings (opt-in)
add ~22ms and, per the benchmark, currently aren't worth it.
