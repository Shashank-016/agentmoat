# dev.to design teardown draft

> Status: DRAFT — for review, not posted.

---
title: "Designing AgentMoat: an enforcement moat for AI agents (and the honest benchmark)"
published: false
tags: ai, security, python, llm
canonical_url: https://github.com/Shashank-016/agentmoat
---

Everyone's shipping "agent security" that scans prompts for injection. I think
that's the wrong primary defense, and I want to walk through the design decisions
behind building the *other* kind — one that enforces on the action, not the
prompt — including the benchmark that shows where it's strong and where it isn't.

## The thesis: defend the action, not the prompt

An autonomous agent's danger surface is the set of **tool calls** it can make.
Prompt injection is just one way to induce a bad tool call; you also have model
mistakes, ambiguous instructions, and compromised context. If your only defense
is recognizing the injection string, you've bet everything on a probabilistic
classifier — and you still haven't stopped the call.

So AgentMoat's hierarchy is deliberately inverted from the market:

1. Argument-level tool firewall (the moat)
2. Tamper-evident audit log
3. Trust provenance across hops
4. Kill switch
5. *...then* prompt-injection detection, as defense-in-depth

## Design decision 1: the firewall inspects arguments, not just names

A name-level allow-list (`write_file` is allowed for the "writer" agent) is table
stakes and not enough — `write_file("/etc/crontab", payload)` passes it. So the
constraint checker flattens a tool call's arguments and runs always-on detectors:

```python
# agentmoat/engine/constraints.py (shape)
_PATH_TRAVERSAL_RE = re.compile(r"\.\.[/\\]|%2e%2e", re.IGNORECASE)
_SSRF_HOSTS = ("169.254.169.254", "localhost", "127.0.0.1", "0.0.0.0",
               "metadata.google.internal")
_SENSITIVE_PATH_RE = re.compile(r"/etc/|/root/|~/\.ssh|id_rsa|\.env|credentials|/proc/", re.I)
```

Plus per-tool path/URL allow- and deny-lists from a YAML policy. The same checker
runs at two enforcement points: the SDK wrapper (before the agent runtime executes
the tool) and the MCP proxy (before the call is forwarded upstream, where blocking
actually prevents execution).

## Design decision 2: enforcement that works from sync, async, and no event loop

The event bus's `emit()` is **synchronous**. LangGraph callbacks and SDK intercepts
run in sync contexts with no event-loop guarantee, so a sync emit is callable from
anywhere; durable persistence is offloaded to a background daemon thread. The
trade-off — anything emitted microseconds before process exit can be lost unless
you `flush()`/`close()` — is explicit, and the proxy CLI drains the bus on shutdown.

## Design decision 3: fail closed, but only where it's safe

If the engine itself throws mid-evaluation (regex blowup, malformed policy), every
call path catches it, emits a critical `engine_error`, and then **blocks** in
`enforce`/`interactive` mode and **allows** in `observe` mode. A broken detector
shouldn't wave everything through when you asked it to enforce — but it also
shouldn't break a production agent that only asked you to *watch*.

## Design decision 4: trust degrades multiplicatively

Reading two external documents doesn't add risk linearly, it compounds —
`score = score * 0.3` per external-content event — and the low score is inherited
across agent handoffs. Injection flips trust to 0 (a qualitative, binary event),
not multiplicatively. It models provenance: every hop through untrusted data
multiplies uncertainty.

## The benchmark — and the numbers I'd rather you not skip

I refuse to publish a single blended "detection rate." Two surfaces, measured
separately against public datasets, one command:

### Argument firewall vs. AgentDojo (609 indirect-injection cases)

| Metric | Result |
|---|---|
| Catch rate | 86.0% (524/609) |
| False positives (339 benign tool calls) | 0.0% |
| Per-call overhead | p50 0.10 ms |

The policy is **derived from each task's benign ground truth** (allow exactly the
tools it legitimately used, deny the rest) — never tuned to the attacks. And the
catch decomposes to: **524 by least-privilege policy, 0 by argument constraints.**
Why 0? AgentDojo's injections move money and post messages; they don't do path
traversal or SSRF, which is what the constraint detectors target. So on *this*
dataset, the moat that fires is least-privilege, and I say so. The 14% misses are
injections that reuse a tool the benign task itself used — semantic misuse the
firewall doesn't model. That's the honest boundary of the approach.

### Injection-text detector vs. deepset/prompt-injections

| Path | Catch | FPR | Latency |
|---|---|---|---|
| Rule-based | 5.3% (14/263) | 0% | 0.10 ms |
| + Embeddings | 5.3% (14/263) | 0% | 22 ms |

5.3% is bad, and the embedding pass added *nothing* here at 200× the cost. This is
the layer I demoted, and the data backs the decision.

## Mapping to OWASP Top 10 for Agentic Applications (2026)

1 covered (ASI02 Tool Misuse), 8 partial, 1 out of scope (ASI04 Supply Chain).
The doc marks every "partial" and explains the gap rather than claiming a clean
sweep.

## What I'd do differently / what's next

- The argument constraints need a dataset that actually exercises them
  (filesystem/SSRF agent attacks) to get a fair catch number — AgentDojo doesn't.
- Injection regex coverage is thin; embeddings need better reference phrases.
- Single-process kill switch; a Redis-backed shared switch is on the roadmap.

Code (MIT): https://github.com/Shashank-016/agentmoat. Tear the design apart in
the comments — especially the trust model and the "enforce the action, not the
prompt" thesis.
