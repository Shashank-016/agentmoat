"""AgentMoat benchmark — single entrypoint.

    python benchmarks/run.py                # rule-based headline numbers
    python benchmarks/run.py --embeddings   # also run the embeddings rows
    python benchmarks/run.py --quick        # subsample for a fast smoke run

Downloads the public datasets (deepset/prompt-injections via HuggingFace,
AgentDojo via its package), runs three scenarios — injection-text detection,
the argument firewall, and per-call latency — and writes a machine-readable
``results/latest.json`` stamped with the git commit and dataset identifiers,
plus the exact derived least-privilege policy to ``derived_policy.yaml``.

The two detection surfaces (injection-text detector and argument firewall) are
reported separately and never blended into one number.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

# Make the repo root importable so `agentmoat` and the `benchmarks` package
# both resolve when this file is run directly as `python benchmarks/run.py`.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import yaml  # noqa: E402

from benchmarks import data_loaders  # noqa: E402
from benchmarks.scenarios import injection_text, latency, tool_firewall  # noqa: E402

RESULTS_DIR = os.path.join(_HERE, "results")
POLICY_PATH = os.path.join(_HERE, "derived_policy.yaml")
RESULTS_PATH = os.path.join(RESULTS_DIR, "latest.json")


def _git(*args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=_ROOT, text=True).strip()
    except Exception:
        return "unknown"


def _commit_info() -> dict[str, str]:
    return {
        "commit": _git("rev-parse", "HEAD"),
        "commit_short": _git("rev-parse", "--short", "HEAD"),
        "dirty": "yes" if _git("status", "--porcelain") else "no",
    }


def _fmt_pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the AgentMoat benchmark.")
    parser.add_argument(
        "--embeddings",
        action="store_true",
        help="Also run the embeddings-based injection path (downloads an ~80MB model).",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Subsample datasets / iterations for a fast smoke run (not for reporting).",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=2000,
        help="Latency iterations (default 2000).",
    )
    args = parser.parse_args()

    if args.embeddings:
        try:
            import sentence_transformers  # noqa: F401
        except ImportError:
            print(
                "ERROR: --embeddings requires sentence-transformers, which is not installed.\n"
                "Install it (pip install 'sentence-transformers>=3.2.0,<4.0') or drop "
                "--embeddings.\nRefusing to run so the benchmark cannot silently report "
                "rule-based numbers as embeddings results.",
                file=sys.stderr,
            )
            return 2

    os.makedirs(RESULTS_DIR, exist_ok=True)

    print("AgentMoat benchmark")
    print("=" * 64)
    commit = _commit_info()
    print(f"commit {commit['commit_short']} (dirty: {commit['dirty']})")

    # --- Injection-text scenario -------------------------------------------
    print("\n[1/3] Injection-text detection (deepset/prompt-injections) ...")
    text_items = data_loaders.load_injection_text(limit=120 if args.quick else None)
    injection_result = injection_text.run(text_items, include_embeddings=args.embeddings)

    # --- Argument-firewall scenario ----------------------------------------
    print("[2/3] Argument firewall (AgentDojo, least-privilege policy) ...")
    adj = data_loaders.load_agentdojo()
    with open(POLICY_PATH, "w", encoding="utf-8") as fh:
        yaml.safe_dump(adj.derived_policy(), fh, sort_keys=True)
    firewall_result = tool_firewall.run(adj, POLICY_PATH)

    # --- Latency scenario ---------------------------------------------------
    print("[3/3] Per-call evaluation latency ...")
    latency_result = latency.run(
        iterations=200 if args.quick else args.iterations,
        include_embeddings=args.embeddings,
    )

    results = {
        "schema": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git": commit,
        "quick_mode": args.quick,
        "datasets": {
            "injection_text": {
                "name": data_loaders.DEEPSET_DATASET,
                "n_items": len(text_items),
            },
            "agentdojo": {
                "version": data_loaders.AGENTDOJO_VERSION,
                "n_user_tasks": firewall_result["n_user_tasks"],
                "n_security_cases": firewall_result["n_security_cases"],
            },
        },
        "scenarios": {
            "injection_text": injection_result,
            "tool_firewall": firewall_result,
            "latency": latency_result,
        },
    }

    with open(RESULTS_PATH, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)

    _print_summary(results)
    print(f"\nWrote {os.path.relpath(RESULTS_PATH, _ROOT)}")
    print(f"Wrote {os.path.relpath(POLICY_PATH, _ROOT)} (exact policy used above)")
    return 0


def _print_summary(results: dict) -> None:
    inj = results["scenarios"]["injection_text"]
    fw = results["scenarios"]["tool_firewall"]
    lat = results["scenarios"]["latency"]

    print("\n" + "=" * 64)
    print("RESULTS")
    print("=" * 64)

    print("\nInjection-text detector (heuristic, defense-in-depth)")
    rb = inj["rule_based"]
    print(
        f"  rule-based   catch {_fmt_pct(rb['catch_rate'])}  "
        f"FPR {_fmt_pct(rb['false_positive_rate'])}  "
        f"(attacks={rb['n_attacks']}, benign={rb['n_benign']})"
    )
    if "embeddings" in inj:
        eb = inj["embeddings"]
        print(
            f"  embeddings   combined catch {_fmt_pct(eb['combined_catch_rate'])}  "
            f"FPR {_fmt_pct(eb['false_positives']['false_positive_rate'])}"
        )
        print(
            f"    attribution: rules-only={eb['caught_by_rules_only']}  "
            f"embeddings-only={eb['caught_by_embeddings_only']}  both={eb['caught_by_both']}"
        )
        print(
            f"    embeddings added {eb['embeddings_added_catches']} catch(es) the rules missed; "
            f"max attack similarity {eb['max_attack_similarity']} "
            f"vs threshold {eb['embedding_threshold']}"
        )

    print("\nArgument firewall (least-privilege policy + always-on constraints)")
    c = fw["catch"]
    fp = fw["false_positives"]
    print(
        f"  catch rate   {_fmt_pct(c['catch_rate'])}  "
        f"({c['caught']}/{fw['n_security_cases']} security cases)"
    )
    print(
        f"    by policy (out-of-scope tool): {c['caught_by_policy']}   "
        f"by argument constraint: {c['caught_by_constraint']}"
    )
    print(
        f"  FPR          {_fmt_pct(fp['false_positive_rate'])}  "
        f"({fp['blocked']}/{fp['n_benign_calls']} benign calls; "
        f"policy={fp['blocked_by_policy']}, constraint={fp['blocked_by_constraint']})"
    )

    print("\nPer-call evaluation latency (engine work, excludes LLM/API call)")
    lrb = lat["rule_based"]
    print(f"  rule-based   p50 {lrb['p50_ms']} ms   p95 {lrb['p95_ms']} ms")
    if "embeddings" in lat:
        le = lat["embeddings"]
        print(f"  embeddings   p50 {le['p50_ms']} ms   p95 {le['p95_ms']} ms")


if __name__ == "__main__":
    raise SystemExit(main())
