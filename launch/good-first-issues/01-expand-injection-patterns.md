# good first issue: Expand injection-detection patterns and re-measure on deepset

**Labels:** `good first issue`, `detection`, `help wanted`

## Background

AgentMoat's injection-text detector is an intentional defense-in-depth heuristic,
but our own benchmark shows it's currently *very* thin: on
[`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections)
the rule-based detector catches only **5.3% (14/263)** of injection-labeled texts
(see `benchmarks/results/latest.json` and the README "Benchmarks" section). The
corpus is diverse and multilingual; our regexes target a narrow set of known
English phrasings.

This is a self-contained, well-scoped way to make a real, *measurable* dent.

## What to do

1. Look at `agentmoat/engine/injection.py` — the `_RAW_PATTERNS` list and the
   `_ATTACK_PHRASES` used for the optional embedding pass.
2. Inspect the **false negatives**: which deepset injection rows we currently miss
   (a small script using `benchmarks/data_loaders.load_injection_text()` plus
   `InjectionDetector().scan()` will list them).
3. Add new regex patterns (and/or embedding reference phrases) that generalize to
   real missed cases — **without** raising the false-positive rate, which is
   currently 0%. Watch out for patterns that fire on benign text.
4. Re-run `python benchmarks/run.py` and report the before/after catch rate **and**
   FPR in the PR.

## Acceptance criteria

- Catch rate on deepset goes up, FPR stays at 0% (or you justify any increase).
- New patterns have unit tests in `tests/test_injection.py`.
- **No tuning to the test set:** patterns must describe a general attack shape, not
  hard-code specific deepset strings. State this explicitly in the PR.

## Pointers

- `agentmoat/engine/injection.py`
- `tests/test_injection.py`
- `benchmarks/scenarios/injection_text.py`
- README → Benchmarks; `benchmarks/README.md` → honesty rules

## Out of scope

Changing the firewall/policy engine, or the embedding model itself.
