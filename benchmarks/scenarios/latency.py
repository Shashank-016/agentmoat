"""Latency scenario: per-call evaluation overhead AgentMoat adds.

This measures the wall-clock cost of the work AgentMoat does *per intercepted
call* — scanning message text for injection, a policy check, and an argument
constraint check — independent of the LLM/API round-trip (which dominates real
latency and which AgentMoat does not change). Reported as p50/p95/mean in
milliseconds over N iterations, embeddings off (the deterministic default path).
The embeddings path is reported separately because it loads an ~80MB model once
and adds per-scan cost.
"""

from __future__ import annotations

import statistics
import time
from typing import Any

from agentmoat.engine.constraints import ArgumentConstraintChecker
from agentmoat.engine.injection import InjectionDetector
from agentmoat.engine.policy import ToolPolicyEngine

_SAMPLE_TEXT = (
    "Please summarize the attached quarterly report and email the three key "
    "findings to the finance team. The document discusses revenue growth, "
    "operating margins, and a planned expansion into the EU market next year."
)
_SAMPLE_TOOL = "write_file"
_SAMPLE_ARGS = {"path": "./output/summary.txt", "content": "Q3 revenue up 12% ..."}


def _percentiles(samples_ms: list[float]) -> dict[str, float]:
    ordered = sorted(samples_ms)
    return {
        "p50_ms": round(statistics.median(ordered), 4),
        "p95_ms": round(ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))], 4),
        "mean_ms": round(statistics.fmean(ordered), 4),
    }


def run(iterations: int = 2000, include_embeddings: bool = False) -> dict[str, Any]:
    detector = InjectionDetector(use_embeddings=False)
    engine = ToolPolicyEngine()  # no policy file: permissive, still runs the checks
    checker = ArgumentConstraintChecker()

    samples: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        detector.scan(_SAMPLE_TEXT)
        engine.check("bench-agent", _SAMPLE_TOOL)
        checker.check(_SAMPLE_TOOL, _SAMPLE_ARGS)
        samples.append((time.perf_counter() - t0) * 1000.0)

    result: dict[str, Any] = {
        "iterations": iterations,
        "rule_based": _percentiles(samples),
    }

    if include_embeddings:
        emb = InjectionDetector(use_embeddings=True)
        # warm-up (first call may JIT / allocate) then measure a smaller N — the
        # embedding forward pass is far slower than the rule path.
        emb.scan(_SAMPLE_TEXT)
        emb_iters = max(50, iterations // 20)
        emb_samples: list[float] = []
        for _ in range(emb_iters):
            t0 = time.perf_counter()
            emb.scan(_SAMPLE_TEXT)
            emb_samples.append((time.perf_counter() - t0) * 1000.0)
        result["embeddings"] = {"iterations": emb_iters, **_percentiles(emb_samples)}

    return result
