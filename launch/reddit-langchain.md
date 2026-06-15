# r/LangChain post draft

> Status: DRAFT — for review, not posted.

## Title

`I built an enforcement layer that firewalls LangGraph tool calls at the argument level — and benchmarked it honestly (MIT)`

## Flair

`Tutorial / Project` (or `Resources`)

## Body

If you're running LangGraph agents that can touch a filesystem, hit internal
APIs, or move money, the scary failure mode isn't the model saying something
weird — it's the model *doing* something weird through a tool. Detecting the
prompt injection that caused it is a coin flip; blocking the resulting action is
not.

**AgentMoat** is an enforcement + audit layer you attach to a graph with one line:

```python
from agentmoat import AgentMoatCallback

graph.invoke(state, config={"callbacks": [AgentMoatCallback(session_id="run-1")]})
```

What it actually does, in order of how much I'd stake on it:

1. **Argument-level tool firewall.** Per-agent allow/deny tool lists *and*
   inspection of the real arguments — path traversal, SSRF (cloud-metadata IP,
   loopback, private ranges), shell metacharacters, sensitive paths. An agent
   allowed to call `write_file` still can't write `/etc/shadow`.
2. **Tamper-evident audit log.** Hash-chained JSONL, `agentmoat audit verify`.
3. **Trust provenance** across agent handoffs.
4. **Kill switch** for a session or the whole process.
5. **Prompt-injection detection** — included, but explicitly the weakest layer
   (defense-in-depth), not the headline.

It's the same drop-in for the Anthropic and OpenAI SDKs, and there's a transparent
MCP proxy if your tools are MCP servers (no agent code change at all).

### The benchmark (and the parts that look bad)

`python benchmarks/run.py`, against public datasets, two surfaces kept separate:

- **Argument firewall vs. AgentDojo (609 indirect-injection cases):** 86.0%
  caught, 0% false positives on benign tool calls, ~0.10ms/call. Honest caveat:
  on AgentDojo that 86% is *least-privilege tool policy* doing the work — the
  argument constraints catch 0 there because AgentDojo's attacks are financial/
  messaging exfiltration, not the filesystem/SSRF class. The README publishes the
  decomposition + the exact derived policy (which is built from each task's benign
  ground truth, so it isn't tuned to the attacks).
- **Injection-text detector vs. deepset/prompt-injections:** 5.3% caught, 0 FP.
  Embeddings added nothing on this set. Yes, 5.3% — that's why I demoted it.

I'd rather show you the weak numbers than have you find them. I also mapped the
controls to the **OWASP Top 10 for Agentic Applications (Dec 2025)**: 1 covered,
8 partial, 1 out of scope.

### Looking for feedback specifically on

- Does the callback capture the tool calls you care about in *your* graph shape
  (multi-agent handoffs, subgraphs)?
- The trust-provenance model (multiplicative degradation on external content) —
  too aggressive, too lax?
- What would make the policy file ergonomic enough that you'd actually write one?

Repo (MIT, alpha): https://github.com/Shashank-016/agentmoat — not selling
anything, no telemetry. Happy to answer design questions in the comments.
