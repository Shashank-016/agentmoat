# good first issue: Add InjecAgent as a second tool-call benchmark source

**Labels:** `good first issue`, `benchmarks`, `help wanted`

## Background

Our firewall benchmark currently uses one tool-call dataset (AgentDojo). Adding a
second, independent source makes the catch-rate number more robust and helps
surface cases our argument constraints actually fire on.
[InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent)
([paper](https://arxiv.org/abs/2403.02691)) is a benchmark of ~1,054 indirect
prompt-injection tool-call cases across domains like finance, email, and smart home.

> Note: InjecAgent is **attack-only** — it has no benign corpus — so it contributes
> to the *catch rate* but not the false-positive rate. Keep that distinction in the
> reporting (we never blend the two surfaces, and we don't claim an FPR from a
> dataset that has no benign traffic).

## What to do

1. Add a loader in `benchmarks/data_loaders.py` that fetches InjecAgent's attack
   cases and normalizes them into the existing `ToolCall` shape (tool name + args).
2. Decide the policy context honestly: InjecAgent cases aren't paired with a benign
   ground-truth task, so document how you derive (or don't derive) a least-privilege
   policy for them, mirroring the principled approach in `benchmarks/README.md`.
   If there's no benign task to derive from, measure only what the *always-on
   argument constraints* catch and label it as such.
3. Extend `benchmarks/scenarios/tool_firewall.py` to report InjecAgent as a
   separate block (don't merge it into the AgentDojo numbers).
4. Add InjecAgent to `benchmarks/requirements.txt` (or document the fetch) and to
   the `benchmarks/README.md` dataset table with its license.

## Acceptance criteria

- `python benchmarks/run.py` produces a distinct InjecAgent result block in
  `results/latest.json`, with catch decomposed into `by_policy` / `by_constraint`.
- The README/`benchmarks/README.md` clearly notes InjecAgent is attack-only (no FPR).
- No change to AgentMoat's engine behavior — this is benchmark-only.

## Pointers

- `benchmarks/data_loaders.py`, `benchmarks/scenarios/tool_firewall.py`
- `benchmarks/README.md` (policy-derivation + honesty rules to mirror)
