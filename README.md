# AgentMoat

[![CI](https://github.com/Shashank-016/agentmoat/actions/workflows/ci.yml/badge.svg)](https://github.com/Shashank-016/agentmoat/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-compatible-6e56cf.svg)](https://modelcontextprotocol.io/)

**An enforcement layer for AI agents.** AgentMoat sits between your agent's decisions and the
actions it takes — inspecting tool-call arguments and blocking dangerous ones before they run,
with a verifiable audit trail and an instant kill switch. Works across the Anthropic & OpenAI
SDKs, LangGraph, and any MCP server; one line to drop in.

![AgentMoat blocking a prompt-injection attack at the tool layer](docs/demo.gif)

## Why

Autonomous agents don't just talk — they *act*: read documents, call tools, write files, hit
APIs. The dangerous moment isn't the model saying something wrong, it's the model *doing*
something wrong — and by the time a bad tool call reaches your filesystem or an internal API,
detecting the prompt that caused it is too late.

AgentMoat is the enforcement layer in between. It checks the **actual arguments** of every tool
call against your policy — path allow/deny lists, SSRF and path-traversal guards, rate limits —
and blocks the call *before it runs*. It records every decision in a **hash-chained audit log**
that can be independently verified line-by-line. It tracks how far each session has **drifted
from trusted input** across agent hops. And it gives you a **one-call kill switch** for any
session, or all of them.

Catching the injection that *tried* to trigger a bad action is useful, but it's a probabilistic
heuristic attackers paraphrase around. So AgentMoat treats injection detection as one
defense-in-depth signal layered on top of enforcement that **doesn't depend on catching the
prompt** — the controls that actually block an action work whether or not the injection was
recognized.

## Benchmarks

Measured against **public** datasets, one command (`python benchmarks/run.py`), numbers
quoted verbatim — including the unflattering ones. Full methodology, caveats, and the exact
derived policy are in [`benchmarks/`](benchmarks/); machine-readable output with the commit
hash is in [`benchmarks/results/latest.json`](benchmarks/results/latest.json).

**The moat — argument firewall vs. [AgentDojo](https://github.com/ethz-spylab/agentdojo) (v1, 609 indirect-injection security cases):**

| Metric | Result |
|--------|--------|
| Attack catch rate | **86.0%** (524 / 609) |
| False-positive rate (on 339 benign tool calls) | **0.0%** |
| Per-call evaluation latency | **p50 0.10 ms · p95 0.13 ms** (excludes the LLM/API call) |

The policy isn't tuned to the attacks: for each AgentDojo task we allow exactly the tools
its *benign* ground-truth run uses and deny the rest (least-privilege), then measure what
that happens to block. **Honest decomposition:** all 524 catches come from least-privilege
*tool policy* denying an out-of-scope tool; AgentMoat's argument-level constraints (path
traversal, SSRF, shell, sensitive paths) account for **0** here, because AgentDojo's attacks
are financial/messaging exfiltration, not the filesystem/network class those detectors
target (they're exercised in `tests/test_constraints.py` instead). The 14% missed are
injections that reuse a tool the benign task itself uses — semantic misuse the firewall
doesn't model.

**Defense-in-depth — injection-text detector vs. [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) (263 injection / 399 benign):**

| Path | Catch rate | FPR | Latency |
|------|-----------|-----|---------|
| Rule-based (default) | 5.3% (14/263) | 0.0% | p50 0.10 ms |
| + Embeddings (opt-in) | 5.3% (14/263) | 0.0% | p50 22 ms |

This is the *heuristic* layer, and the numbers say so plainly: regex catches a low 5.3% of
this diverse, multilingual corpus, and the opt-in embedding pass added **no** catches here
while costing ~200× the latency. That's exactly why AgentMoat leads with enforcement and
treats injection detection as a secondary signal — not the thing standing between the model
and the action.

> Generated with `python benchmarks/run.py --embeddings` against `deepset/prompt-injections`
> and AgentDojo `v1`. Reproduce with the steps in [`benchmarks/README.md`](benchmarks/README.md);
> the exact commit is recorded in `results/latest.json`.

## Install

```bash
pip install agentmoat

# with extras
pip install "agentmoat[langgraph,openai]"
```

For development (editable install from source):

```bash
git clone https://github.com/Shashank-016/agentmoat
cd agentmoat
pip install -e ".[langgraph,openai]"   # extras optional; base install works on its own
```

## Quick start (30 seconds)

```python
import anthropic
from agentmoat import GuardedClient

# Wrap your existing client — same interface as anthropic.Anthropic()
client = GuardedClient(
    anthropic.Anthropic(),
    agent_id="researcher",
    policy_path="policy.yaml",   # optional
    mode="observe",              # "observe" | "enforce" | "interactive"
)

# Use it exactly as before. AgentMoat scans inputs, checks tool calls,
# logs every event, and (in enforce mode) blocks dangerous actions.
resp = client.messages.create(
    model="claude-haiku-4-5-20251001",
    max_tokens=512,
    messages=[{"role": "user", "content": "Summarize this document..."}],
)
```

See it catch a real attack:

```bash
python examples/mcp_proxy_demo.py
# An agent reads a poisoned document and tries a privileged write —
# AgentMoat blocks it at the tool layer and prints a session report.
```

## Add AgentMoat to your own agent

One line at the point you create your client or graph. Everything downstream is instrumented.

**Anthropic SDK**
```python
from anthropic import Anthropic
from agentmoat import GuardedClient

client = GuardedClient(Anthropic(), agent_id="my-agent", policy_path="policy.yaml", mode="enforce")
```

**OpenAI SDK**
```python
from openai import OpenAI
from agentmoat import GuardedOpenAI

client = GuardedOpenAI(OpenAI(), agent_id="my-agent", policy_path="policy.yaml", mode="enforce")
```

**LangGraph** — attach the callback to any graph/runnable:
```python
from agentmoat import AgentMoatCallback

graph.invoke(state, config={"callbacks": [AgentMoatCallback(session_id="run-1")]})
```

**Any MCP tool server** — run AgentMoat as a transparent proxy, no agent code change at all.
Point your MCP client at AgentMoat instead of the real server:
```bash
agentmoat mcp proxy stdio \
  --upstream-cmd "npx -y @modelcontextprotocol/server-filesystem /data" \
  --agent-id my-agent \
  --policy policy.yaml \
  --mode enforce
```

Async variants (`AsyncGuardedClient`, `AsyncGuardedOpenAI`) and streaming are supported with the
same interface. Events flow to an in-memory bus, an optional SQLite store, and a hash-chained
JSONL audit log; view them via the bundled FastAPI service and React dashboard (see below).

---

## Policy File

```yaml
version: "1"
agents:
  researcher:
    allowed_tools: [web_search, read_file]
    denied_tools:  [write_file, execute_code]
    rate_limits:
      web_search: 10/minute

  writer:
    allowed_tools: [write_file, read_file]
    denied_tools:  [web_search, execute_code]
```

### Argument constraints

Tool *names* are only half the story — `write_file("/etc/crontab", payload)` passes a
name-level check for any agent allowed to use `write_file`. `ToolPolicyEngine.check_arguments()`
inspects the *arguments* of a tool call, combining always-on built-in detectors with
per-tool rules declared in the policy file:

```yaml
agents:
  writer:
    tool_constraints:
      write_file:
        path_allowlist: ["/tmp/**", "./output/**"]   # only these globs are permitted
        path_denylist:  ["/etc/**", "~/.ssh/**"]      # these are always blocked
        max_arg_length: 10000                         # flag oversized argument values
      fetch:
        url_denylist: ["169.254.169.254", "localhost", "10.*"]
        # url_allowlist, arg_denylist also supported
```

Built-in detectors run on every tool call regardless of configuration:

| Detector | Flag | Triggers on |
|----------|------|-------------|
| Path traversal | `constraint:path_traversal` | `../`, `..\`, or URL-encoded `%2e%2e` in any argument |
| SSRF targets | `constraint:ssrf_target` | URLs/hosts pointing at `169.254.169.254`, `localhost`, `127.0.0.1`, RFC-1918 ranges, `metadata.google.internal` |
| Shell metacharacters | `constraint:shell_metachar` | `;`, `\|`, `&&`, `` ` ``, `$(`, `>`, `<` in arguments to tools whose name suggests command execution (`exec`, `shell`, `command`, `run`, `bash`, `sh`) |
| Sensitive path access | `constraint:sensitive_path` | `/etc/`, `/root/`, `~/.ssh`, `id_rsa`, `.env`, `credentials`, `/proc/` |

Violations are emitted as `policy_violation` events with `severity="critical"` and raise
`AgentMoatException` in `enforce` mode — both from the SDK wrappers (checked against the
arguments the model produced, before the agent runtime executes the tool) and from the MCP
proxy (checked before the call is forwarded upstream, where blocking actually prevents execution).

---

## What Gets Detected

| Threat | Detection Method | Default Severity |
|--------|-----------------|-----------------|
| Jailbreak attempt | Regex: "ignore previous instructions", "you are now DAN" | Critical |
| System prompt exfiltration | Regex: "print your system prompt", "repeat everything above" | Critical |
| Role override | Regex: "act as if you have no restrictions" | Critical |
| Tool abuse via injection | Regex: "call the write_file tool" | Critical |
| Indirect injection (docs, web) | Regex + embedding similarity | Warning/Critical |
| Tool policy violation | YAML policy engine | Critical |
| Rate limit exceeded | Sliding window counter | Critical |
| Low-trust agent calling sensitive tools | Trust score degradation | Warning |
| Multi-agent trust chain poisoning | Multiplicative provenance tracking | Warning |

---

## OWASP Top 10 for Agentic Applications (2026)

How AgentMoat's controls line up against the
[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
(OWASP GenAI Security Project, published 9 Dec 2025). We're deliberate about not overstating this:
AgentMoat is a *tool-action enforcement and audit* layer, so it directly **covers** tool misuse and
is **partial** on most of the rest — shrinking blast radius and adding visibility rather than fully
preventing the root cause. Full rationale per item is in [`docs/owasp-mapping.md`](docs/owasp-mapping.md).

| OWASP ID | Risk | Status | AgentMoat control |
|----------|------|--------|-------------------|
| ASI01 | Agent Goal Hijack | 🟡 Partial | Injection detection (heuristic) + trust provenance; downstream tool calls still enforced |
| ASI02 | Tool Misuse and Exploitation | 🟢 Covered | Policy engine + argument-level firewall, enforced at SDK wrappers **and** MCP proxy |
| ASI03 | Identity and Privilege Abuse | 🟡 Partial | Per-agent tool least-privilege; secret redaction in logs (no credential/identity management) |
| ASI04 | Agentic Supply Chain Vulnerabilities | ⚪ Out of scope | Forensic visibility via audit log only |
| ASI05 | Unexpected Code Execution | 🟡 Partial | Shell-metachar constraints, deny exec-style tools (no sandbox) |
| ASI06 | Memory and Context Poisoning | 🟡 Partial | Trust provenance + indirect-injection detection (no memory-store integrity) |
| ASI07 | Insecure Inter-Agent Communication | 🟡 Partial | Trust propagation + audit of handoffs (no transport auth/encryption) |
| ASI08 | Cascading Failures | 🟡 Partial | Kill switch, rate limits, bounded state, fail-closed engine |
| ASI09 | Human-Agent Trust Exploitation | 🟡 Partial | Approval gate with full call context + verifiable audit trail |
| ASI10 | Rogue Agents | 🟡 Partial | Tool/argument enforcement, trust flags, kill switch, audit log |

**1 covered · 8 partial · 1 out of scope.** AgentMoat is one layer — strongest at constraining and
recording tool actions — meant to sit alongside identity, sandboxing, and supply-chain controls.

---

## Response modes

Every guarded client, callback, and the MCP proxy take a `mode`:

| Mode | Behavior |
|------|----------|
| `"observe"` (default) | Detect and log everything — never interrupts the agent. |
| `"enforce"` | Raise `AgentMoatException` (or return a JSON-RPC error from the MCP proxy) on any hard violation. A fixed, pre-decided policy. |
| `"interactive"` | Route violations to a human (or programmatic approver) for a real-time decision via `ApprovalGate`. A "deny" blocks the call just like enforce mode; an "approve" lets it through. |

`"interactive"` mode is for situations where a blanket policy is too coarse — let
a human apply judgment to a specific borderline case instead of pre-encoding
every exception:

```python
from agentmoat import GuardedClient, ApprovalGate
from agentmoat.control import ApprovalRequest, ApprovalDecision

def slack_approval_handler(request: ApprovalRequest) -> ApprovalDecision:
    # Post to Slack, wait for a thumbs-up/thumbs-down reaction, etc.
    ...
    return "approve"  # or "deny"

client = GuardedClient(
    anthropic.Anthropic(),
    agent_id="researcher",
    mode="interactive",
    approval_gate=ApprovalGate(handler=slack_approval_handler),
)
```

Each request emits `approval_required`, then `approval_granted` or
`approval_denied`, so the full decision trail lands in the audit log. The
default handler (when no `approval_gate=` is supplied) prompts on the CLI with
a y/N confirmation — fine for local development, but register your own handler
(Slack, a web UI, a queue) for anything running unattended. A misbehaving or
exception-raising handler defaults to `"deny"` — approval gates fail closed.

Note: `trust_flag` warnings never hard-block in `enforce` mode (a low trust
score alone shouldn't halt an agent), but in `interactive` mode they still
route through the approval gate — a human's explicit "deny" blocks the call.
This gives interactive mode finer-grained control than a blanket policy.

### Kill switch

Independent of `mode`, any session — or every session in the process — can be
halted immediately via `KillSwitch`:

```python
from agentmoat.control import get_default_kill_switch

switch = get_default_kill_switch()
switch.kill_session("session-123")   # halt one session
switch.kill_all()                    # halt every session in this process
switch.revive_session("session-123") # restore it
switch.status()                      # {"global": False, "killed_sessions": [...]}
```

A killed session's next intercepted action raises `AgentMoatKilled` (a subclass
of `AgentMoatException`) — or, for the MCP proxy, returns a JSON-RPC error
(`AGENTMOAT_SESSION_KILLED`) — *before* any API call or tool execution happens.
A critical `session_end` event with `flags=["kill:tripped"]` is emitted first,
so the halt is visible in the audit trail.

The same switch is reachable over HTTP once the audit API is running:

```bash
curl -X POST http://localhost:8000/control/kill/session-123
curl -X POST http://localhost:8000/control/kill-all
curl -X POST http://localhost:8000/control/revive/session-123
curl http://localhost:8000/control/status
```

These endpoints affect sessions in the API process only — a multi-process
deployment needs a shared backing store (see Roadmap) for one trip to halt
every worker. They're also unauthenticated for now; put them behind your own
auth/network controls before exposing them.

---

## Tamper-evident audit log

`AuditLogger` (passed via `audit_log=` to any guarded client/callback) writes one JSON
object per line to a durable JSONL file. By default (`chained=True`) every record also
carries `prev_hash` — the SHA-256 `record_hash` of the previous line, with a genesis value
of 64 zeros for the first line in a fresh file — and its own `record_hash`, a digest over
the record's canonical JSON plus `prev_hash`. Editing or deleting any line breaks the link
to the next record, so tampering is always detectable, not just guessable. The chain
survives process restarts (it resumes from the last line on disk) and rotations (the new
file's first record continues from the rotated file's last hash).

```bash
agentmoat audit verify agentmoat_audit.jsonl
# ✓ Chain intact — 1,432 records verified
#   (or, if a line was edited or removed:)
# ✗ Chain broken at line 87 — record was modified or a prior line was deleted

agentmoat audit tail agentmoat_audit.jsonl -n 50
agentmoat audit stats agentmoat_audit.jsonl   # counts by event_type and severity
```

This gives you a forensic trail suitable for SOC 2 / ISO 27001 evidence: an auditor (or an
incident responder) can independently confirm that the log they're looking at is the
complete, unaltered record AgentMoat produced — not a reconstruction. It does not, by
itself, prove *who* tampered with a file; pair it with filesystem-level access controls and
off-host replication for full chain-of-custody guarantees.

---

## Running the API + Dashboard

```bash
# 1. Install
pip install -e ".[langgraph]"

# 2. Start the audit API
uvicorn api.main:app --reload

# 3. Start the dashboard
cd dashboard
npm install
npm run dev
# → http://localhost:5173

# 4. Run the demo
python examples/langgraph_demo.py
```

See [`dashboard/README.md`](dashboard/README.md) for dashboard-specific setup, including how to
authenticate against an API started with `AGENTMOAT_API_KEY` set.

---

## Running Tests

```bash
pytest
```

---

## Trust Scoring

AgentMoat tracks *information provenance* across agent hops. When a session processes external content (a file, a web page, a user upload), its trust score degrades:

```
Initial:          1.0  (TRUSTED  — human instructions)
After file read:  0.3  (EXTERNAL — external content processed)
After handoff:    0.21 (EXTERNAL — downstream agent inherits low trust)
After injection:  0.0  (UNTRUSTED — flagged)
```

When trust drops below 0.5, any attempt to call a sensitive tool (write, execute, send, delete) emits a `trust_flag` warning even if the tool is otherwise policy-allowed.

---

## Roadmap

- [x] **OpenAI SDK support** — `GuardedOpenAI` / `AsyncGuardedOpenAI` wrap `openai.OpenAI` / `AsyncOpenAI`
- [x] **Async GuardedClient** — `AsyncGuardedClient` wraps `AsyncAnthropic` for async codebases
- [x] **Streaming support** — `GuardedStream` / `AsyncGuardedStream` intercept `messages.stream()`
- [x] **MCP server integration** — transparent stdio + SSE proxy for Model Context Protocol
- [x] **Tamper-evident audit log** — SHA-256 hash-chained JSONL with `agentmoat audit verify`
- [x] **Human-in-the-loop approval** — `mode="interactive"` routes violations through `ApprovalGate`
- [x] **Kill switch** — halt any session (or every session) immediately, programmatically or via `/control`
- [ ] **OpenTelemetry export** — emit spans/traces to any OTEL-compatible backend
- [ ] **Multi-process bus** — Redis-backed EventBus for distributed agent deployments
- [ ] **Slack/PagerDuty alerting** — push critical events to on-call channels
- [ ] **SARIF export** — machine-readable security findings for CI integration
- [ ] **Policy hot-reload** — watch policy.yaml for changes without restart

---

## License

MIT — see [LICENSE](LICENSE)
