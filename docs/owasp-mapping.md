# AgentMoat ↔ OWASP Top 10 for Agentic Applications (2026)

This document maps AgentMoat's controls to the
[OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/),
published by the OWASP GenAI Security Project on 9 December 2025. The list catalogs
system-level risks specific to autonomous AI agents — systems that *plan, use tools, hold
memory, and act across multiple steps* — rather than the model-level request/response risks
of the [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/).

**Sources**

- OWASP GenAI Security Project — *Top 10 for Agentic Applications for 2026* (resource page / PDF):
  <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- OWASP GenAI Security Project — release announcement, 9 Dec 2025:
  <https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/>

## How to read the status column

| Status | Meaning |
|--------|---------|
| **Covered** | AgentMoat provides a direct, enforceable control that materially mitigates this risk. |
| **Partial** | AgentMoat reduces the blast radius or improves visibility, but does not fully prevent the risk — it depends on a heuristic, only addresses part of the attack surface, or constrains the *consequences* rather than the root cause. |
| **Out of scope** | AgentMoat provides little or no control here; mitigation belongs to another layer (identity provider, supply-chain tooling, sandbox, etc.). |

AgentMoat is fundamentally a *tool-action enforcement and audit layer*. Its strongest, most
direct coverage is **ASI02 (Tool Misuse)** — argument-level inspection of every tool call. Most
other items are marked **Partial**: AgentMoat's enforcement and audit primitives shrink the blast
radius of an attack that has already partly succeeded, but they are not a complete control for the
root cause. We deliberately do **not** claim broad "coverage" of the list.

---

## Mapping

### ASI01 — Agent Goal Hijack · **Partial**

*An attacker alters the agent's objectives through malicious content (e.g. a poisoned document or
web page / indirect prompt injection).*

- **InjectionDetector** (`agentmoat/engine/injection.py`) flags known hijack/jailbreak patterns in
  inputs and tool results (regex + optional embedding similarity). This is a **heuristic** — it
  catches known phrasings and close paraphrases, not novel ones.
- **TrustScorer** (`agentmoat/engine/trust.py`) degrades a session's trust score every time it
  ingests external content, so a session that has read untrusted data is treated as lower-trust
  for subsequent sensitive tool calls.
- **Argument-level firewall + policy** still enforce on the *resulting* tool call even if the
  hijack itself goes undetected — limiting what a hijacked agent can actually do.

**Why partial:** AgentMoat cannot reliably *prevent* goal hijack (detection is probabilistic), but
it constrains the downstream actions a hijacked agent can take and degrades trust on tainted
sessions.

### ASI02 — Tool Misuse and Exploitation · **Covered**

*The agent uses legitimate tools in unsafe ways — wrong arguments, dangerous targets, excessive
frequency.*

- **ToolPolicyEngine** (`agentmoat/engine/policy.py`): per-agent allow/deny tool lists and
  per-tool rate limits (deny-list checked before allow-list, fail-safe).
- **ArgumentConstraintChecker** (`agentmoat/engine/constraints.py`): always-on inspection of the
  *actual arguments* — path traversal (`../`, URL-encoded variants), SSRF targets (link-local
  metadata IPs, `localhost`, RFC-1918), shell metacharacters for exec-style tools, sensitive paths
  (`/etc`, `~/.ssh`, `.env`, `id_rsa`). Plus per-tool `path_allowlist/denylist`,
  `url_allowlist/denylist`, `arg_denylist`, and `max_arg_length`.
- Enforced both at the **SDK wrappers** (before the agent runtime executes the tool) and at the
  **MCP proxy** (before the call is forwarded upstream, where blocking actually prevents execution).

**Why covered:** This is AgentMoat's core competency — name-level *and* argument-level enforcement
that blocks a dangerous call before it runs, in `enforce` mode.

### ASI03 — Identity and Privilege Abuse · **Partial**

*Agents inherit, share, or escalate high-privilege credentials; act without distinct governed
identities.*

- **ToolPolicyEngine** enforces *least privilege at the tool level* — each `agent_id` gets an
  explicit allow/deny set, so a "researcher" agent cannot invoke `write_file`/`execute_code` even
  if it tries.
- The **audit log** records which `agent_id` attempted which tool, supporting after-the-fact
  privilege review.

**Why partial:** AgentMoat governs *what tools an agent identity may call*, but it does **not**
manage credentials, tokens, OAuth scopes, or authentication. Identity issuance and credential
hygiene belong to your identity provider / secrets manager. (AgentMoat does redact detected
secrets from persisted events — see `agentmoat/redaction.py` — which reduces credential leakage
into logs, but that is not identity management.)

### ASI04 — Agentic Supply Chain Vulnerabilities · **Out of scope**

*Compromised third-party tools, plugins, models, or data sources loaded at runtime.*

- AgentMoat does not vet, pin, or scan the tools/servers/models an agent depends on. The MCP proxy
  sits in front of a tool server but trusts that server's identity and integrity.
- The only adjacent benefit: the **tamper-evident audit log** gives forensic visibility if a
  compromised component is later identified, and policy/argument constraints still bound what a
  compromised tool *server* is asked to do.

**Why out of scope:** Supply-chain integrity (SBOMs, dependency pinning, model/plugin provenance)
is a different layer. AgentMoat assumes the upstream tool server it proxies is the one you
intended to run.

### ASI05 — Unexpected Code Execution · **Partial**

*Agents generate and run code or shell commands unsafely.*

- **ArgumentConstraintChecker** flags shell metacharacters (`;`, `|`, `&&`, `` ` ``, `$(`, `>`,
  `<`) in arguments to tools whose names suggest command execution (`exec`, `shell`, `command`,
  `run`, `bash`, `sh`).
- **ToolPolicyEngine** lets you deny code-execution tools outright per agent (`denied_tools:
  [execute_code]`).

**Why partial:** AgentMoat can block obvious command-injection arguments and forbid exec-style
tools, but it does **not** sandbox or isolate code that *is* permitted to run. Pair it with a real
execution sandbox (containers, gVisor, seccomp) for defense in depth.

### ASI06 — Memory and Context Poisoning · **Partial**

*Attackers poison long-term memory or RAG data so future decisions are biased.*

- **TrustScorer** tracks information provenance: any context derived from external content lowers
  the session's trust score, and that degradation is inherited across agent handoffs
  (multiplicative), modeling poisoned context flowing downstream.
- **InjectionDetector** runs on document/tool-result content (indirect injection), catching known
  poisoning payloads as they enter.

**Why partial:** AgentMoat observes and scores poisoned context entering a session, but it does
**not** secure the integrity of an external memory/vector store itself (write authorization,
content signing, retrieval validation). Detection of poisoning is heuristic.

### ASI07 — Insecure Inter-Agent Communication · **Partial**

*Multi-agent messages lack authentication/encryption, enabling spoofing, tampering, replay.*

- **TrustScorer** propagates provenance across agent hops, so a handoff from a low-trust agent
  yields a low-trust downstream session (models "trust chain poisoning").
- The **audit log** records handoffs and the events around them for after-the-fact review.

**Why partial:** AgentMoat gives *observability and trust propagation* over multi-agent handoffs,
but it does **not** secure the transport between agents (mutual auth, message signing, encryption,
nonce/replay protection). Those belong to your inter-agent messaging layer.

### ASI08 — Cascading Failures · **Partial**

*A fault or compromise in one agent propagates and amplifies across the system.*

- **KillSwitch** (`agentmoat/control.py`) is a process-wide circuit breaker: `kill_all()` halts
  every in-process session immediately, programmatically or via `POST /control/kill-all`.
- **Rate limits** (sliding-window per agent+tool) cap runaway tool invocation.
- **Bounded state** (`agentmoat/engine/_state.py`, TTL+LRU) prevents unbounded internal-memory
  growth from long runs.
- **Fail-closed** on internal engine errors in `enforce`/`interactive` mode stops a broken detector
  from waving everything through.

**Why partial:** These are blast-radius and circuit-breaker controls — they let an operator (or a
limit) halt a cascade — but AgentMoat does not automatically detect a developing cascade across a
distributed fleet, and the kill switch is in-process only (a multi-process deployment needs a
shared backing store; see Roadmap).

### ASI09 — Human-Agent Trust Exploitation · **Partial**

*Humans over-trust agent outputs; agents exploit authority/anthropomorphism to drive harmful
actions.*

- **Interactive mode / ApprovalGate** routes risky actions to a human with the concrete tool call
  and its arguments in front of them, so approval is an informed decision rather than blind trust.
  The gate **fails closed** (a misbehaving handler defaults to "deny").
- The **tamper-evident audit log** gives reviewers an independently verifiable record instead of
  trusting the agent's own account of what it did.

**Why partial:** AgentMoat *supports* human oversight with evidence and decision checkpoints, but
it cannot stop a human from over-trusting the agent. This risk is mostly organizational
(process, training, oversight design).

### ASI10 — Rogue Agents · **Partial**

*A misaligned or compromised agent acts as an insider threat while appearing legitimate.*

- **ToolPolicyEngine + ArgumentConstraintChecker** bound what *any* agent — rogue or not — can do,
  regardless of intent.
- **TrustScorer** flags sensitive tool calls from low-trust sessions (`trust_flag`).
- **KillSwitch** halts a specific session (`kill_session`) or all of them the moment a rogue agent
  is identified.
- **Tamper-evident audit log** makes the rogue agent's actions visible and non-repudiable.

**Why partial:** AgentMoat constrains and can halt a rogue agent and makes its behavior auditable,
but *detecting* subtle misalignment (an agent doing permitted actions toward a wrong goal) is
largely outside its heuristics — identification still depends on policy design and human review.

---

## Summary

| OWASP ID | Risk | AgentMoat status | Primary controls |
|----------|------|------------------|------------------|
| ASI01 | Agent Goal Hijack | Partial | Injection detector (heuristic), trust provenance, downstream tool enforcement |
| ASI02 | Tool Misuse and Exploitation | **Covered** | Policy engine + argument-level firewall (SDK wrappers & MCP proxy) |
| ASI03 | Identity and Privilege Abuse | Partial | Per-agent tool least-privilege, secret redaction in logs |
| ASI04 | Agentic Supply Chain Vulnerabilities | Out of scope | (Audit log gives forensic visibility only) |
| ASI05 | Unexpected Code Execution | Partial | Shell-metachar constraints, deny exec-style tools (no sandbox) |
| ASI06 | Memory and Context Poisoning | Partial | Trust provenance, indirect-injection detection (no store integrity) |
| ASI07 | Insecure Inter-Agent Communication | Partial | Trust propagation + audit of handoffs (no transport auth/crypto) |
| ASI08 | Cascading Failures | Partial | Kill switch, rate limits, bounded state, fail-closed |
| ASI09 | Human-Agent Trust Exploitation | Partial | Approval gate with full context, verifiable audit trail |
| ASI10 | Rogue Agents | Partial | Tool/argument enforcement, trust flags, kill switch, audit log |

**Coverage at a glance:** 1 covered, 8 partial, 1 out of scope. AgentMoat is an enforcement and
audit layer, not a complete agentic-security platform — it is strongest at constraining and
recording *tool actions*, and is intended to be one layer among identity, sandboxing, and
supply-chain controls.
