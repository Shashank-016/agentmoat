# AgentMoat benchmarks

Reproducible measurements of AgentMoat against **public** datasets. One command:

```bash
# from the repo root, ideally in a fresh virtualenv (see note below)
pip install -e .
pip install -r benchmarks/requirements.txt
python benchmarks/run.py                 # rule-based headline numbers
python benchmarks/run.py --embeddings    # also runs the embeddings rows (~80MB model)
python benchmarks/run.py --quick         # fast smoke run (subsampled; NOT for reporting)
```

Outputs:

- `results/latest.json` — machine-readable metrics, stamped with the **git commit**,
  dataset identifiers, and a UTC timestamp.
- `derived_policy.yaml` — the **exact** least-privilege policy used by the firewall
  scenario, regenerated each run so the catch-rate number is reproducible and auditable.

> **Environment note.** AgentDojo pins a newer `langchain-core` than AgentMoat's
> `[langgraph]` extra, so installing both in one environment prints a harmless pip
> dependency-resolver warning. Use a separate virtualenv for the benchmark if you want a
> clean resolver. AgentMoat's own test suite is unaffected.

## What is measured

AgentMoat has **two independent detection surfaces**, benchmarked separately and never
blended into a single headline number:

### 1. Injection-text detector (heuristic, defense-in-depth)

`InjectionDetector` scans text (prompts, document/tool-result content) for known
injection/jailbreak patterns — regex by default, optional embedding similarity. A text is
*flagged* if any pattern matches.

- **Dataset:** [`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections)
  (Apache-2.0, ungated, 662 labeled texts: `label=1` injection, `label=0` benign).
- **Metrics:** catch rate (recall on `label=1`) and false-positive rate (`label=0` flagged).
- **Headline = rule-based**, because that is the deterministic, dependency-light path you
  get out of the box. The `--embeddings` row is reported separately so the model-load and
  added latency are an explicit tradeoff, not folded into the headline.

This surface is deliberately *not* AgentMoat's primary value — it is a probabilistic
heuristic attackers paraphrase around. Expect a modest catch rate; that is the honest
point of "defense-in-depth."

### 2. Argument firewall (the "moat")

`ToolPolicyEngine` (allow/deny + rate limits) plus the always-on `ArgumentConstraintChecker`
(path traversal, SSRF targets, sensitive paths, shell metacharacters), evaluated on real
tool calls.

- **Dataset:** [AgentDojo](https://github.com/ethz-spylab/agentdojo) (MIT) — agent tasks
  across banking, Slack, travel, and workspace suites, each with a benign ground-truth tool
  sequence and paired indirect-prompt-injection tasks. We read each task's declared
  ground-truth `FunctionCall`s **statically — no LLM is run**, so the numbers are
  deterministic and free.
- **Metrics:** catch rate over the (user-task × injection-task) security cases, and
  false-positive rate over benign ground-truth calls.

#### How the policy is derived (and why it is not overfit)

For each AgentDojo **user task**, `allowed_tools` is set to *exactly the tools its benign
ground-truth sequence uses* — everything else is implicitly denied by AgentMoat's
allow-list semantics. Each injection task is then evaluated **in the context of that user
task's policy**. The policy is derived **purely from benign behaviour**, never from the
attack set, so it is principled least-privilege rather than a deny-list hand-tuned to the
test cases. The full generated policy is written to `derived_policy.yaml`.

A catch is decomposed into:

- **`by_policy`** — the attack needs a tool outside the user task's least-privilege
  allow-list (least-privilege did the work).
- **`by_constraint`** — a tool call's *arguments* tripped an always-on constraint.

This decomposition matters: on AgentDojo, the catch is **almost entirely `by_policy`**.
That is honest and expected — AgentDojo's injection goals are financial transfers and
message/data exfiltration (e.g. "send money to attacker", "post to a Slack channel"), which
typically require a tool the benign task never used, so least-privilege denies them. They do
**not** exercise AgentMoat's argument detectors (path traversal, SSRF, shell, sensitive
paths), which target a *filesystem/network* attack class AgentDojo does not cover — so
`by_constraint` is near zero here. Those detectors are exercised instead by the unit tests
(`tests/test_constraints.py`) and the `examples/` demos. We do **not** claim the AgentDojo
catch rate as evidence of argument-level inspection; read it as evidence of least-privilege
tool policy.

Attacks that AgentMoat **misses** here are the honest tail: injections that reuse a tool the
benign task *also* legitimately uses (e.g. a benign task that sends money, with the injection
sending money to a different recipient), where the malicious intent is in semantics the
firewall does not model.

#### Why the firewall FPR is what it is

The least-privilege policy allows the benign tools by construction, so **policy-level
false positives are 0 by definition**. The reported firewall FPR therefore isolates the
**always-on argument constraints** firing on legitimate tool-call arguments — the number
that actually tells you whether the constraints are too aggressive on real traffic.

### 3. Per-call latency overhead

Wall-clock cost of the work AgentMoat does *per intercepted call* — an injection scan, a
policy check, and an argument check — **excluding** the LLM/API round-trip, which dominates
real latency and which AgentMoat does not change. Reported as p50/p95/mean over N iterations
(default 2000), rule-based by default; the embeddings forward pass is reported separately.

## Honesty rules followed here

- Two surfaces reported separately; never merged into one "detection rate."
- Headline numbers are the deterministic rule-based path; embeddings shown as a separate,
  explicitly costlier row.
- The firewall policy is derived from benign behaviour only and published verbatim.
- Catch is decomposed (policy vs. argument constraint) so the source of the number is
  visible, and the limitations above are stated rather than buried.
- Nothing is tuned to the test set; thresholds are AgentMoat's shipped defaults.

## Reproducing the README numbers

The "Benchmarks" section of the top-level README quotes `results/latest.json` for a specific
commit. Re-run `python benchmarks/run.py` at that commit to regenerate it; small drift in the
injection-text numbers is possible if the upstream dataset is updated by its maintainers.
