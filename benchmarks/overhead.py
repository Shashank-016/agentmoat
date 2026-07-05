"""AgentMoat overhead micro-benchmark.

    python benchmarks/overhead.py                 # default iterations
    python benchmarks/overhead.py --iterations N  # override sample count

Measures the wall-clock cost AgentMoat adds, independent of the LLM/API call
(which dominates real latency and which AgentMoat does not change):

  (a) injection scan per message      — InjectionDetector.scan (rule mode)
  (b) argument-constraint check        — ArgumentConstraintChecker.check per tool call
  (c) end-to-end MCP proxy overhead    — MCPProxy.handle vs. a direct upstream call

For (c) the upstream server is a trivial in-process mock with an effectively
zero-cost ``send()`` — so the measured delta is *purely* the work AgentMoat's
proxy adds (request parsing + the full interceptor: injection + argument
constraints + tool policy + trust + event emission), not subprocess/IPC. A real
stdio server would add its own transport latency identically to both the direct
and proxied paths, so it would cancel out of the overhead delta anyway.

Dependency-free beyond the existing package + dev deps.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import platform
import statistics
import sys
import time
from typing import Any

# Make the repo root importable so `agentmoat` resolves when this file is run
# directly as `python benchmarks/overhead.py`.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from agentmoat.bus import EventBus  # noqa: E402
from agentmoat.engine.constraints import ArgumentConstraintChecker  # noqa: E402
from agentmoat.engine.injection import InjectionDetector  # noqa: E402
from agentmoat.mcp.interceptor import MCPInterceptor  # noqa: E402
from agentmoat.mcp.models import MCPRequest, MCPResponse  # noqa: E402
from agentmoat.mcp.proxy import MCPProxy  # noqa: E402

_SAMPLE_TEXT = (
    "Please summarize the attached quarterly report and email the three key "
    "findings to the finance team. The document discusses revenue growth, "
    "operating margins, and a planned expansion into the EU market next year."
)
_SAMPLE_TOOL = "write_file"
_SAMPLE_ARGS: dict[str, Any] = {
    "path": "./output/summary.txt",
    "content": "Q3 revenue up 12% ...",
}


class _MockUpstream:
    """Stand-in for StdioUpstreamClient/SSEUpstreamClient.

    ``send()`` returns immediately with a canned result, so its cost is
    negligible and identical on the direct and proxied paths — isolating the
    proxy's own overhead in the delta.
    """

    async def send(self, request: MCPRequest) -> MCPResponse:
        return MCPResponse(id=request.id, result={"ok": True})


def _percentiles(samples_ms: list[float]) -> dict[str, float]:
    ordered = sorted(samples_ms)
    return {
        "p50_ms": round(statistics.median(ordered), 4),
        "p95_ms": round(ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))], 4),
        "mean_ms": round(statistics.fmean(ordered), 4),
    }


def _measure(fn, iterations: int, warmup: int = 50) -> dict[str, float]:
    for _ in range(warmup):
        fn()
    samples: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return _percentiles(samples)


def bench_injection_scan(iterations: int) -> dict[str, float]:
    detector = InjectionDetector(use_embeddings=False)
    return _measure(lambda: detector.scan(_SAMPLE_TEXT), iterations)


def bench_argument_constraints(iterations: int) -> dict[str, float]:
    checker = ArgumentConstraintChecker()
    return _measure(lambda: checker.check(_SAMPLE_TOOL, _SAMPLE_ARGS), iterations)


def bench_mcp_proxy(iterations: int) -> dict[str, dict[str, float]]:
    """Measure a full proxied tools/call vs. a direct upstream call."""
    bus = EventBus(store=None)  # in-memory only, no background persistence
    interceptor = MCPInterceptor(
        agent_id="bench-agent",
        session_id="bench-session",
        bus=bus,
        policy_path=None,  # permissive: the call is allowed, so every check runs
        mode="observe",
    )
    upstream = _MockUpstream()
    proxy = MCPProxy(upstream, interceptor, mode="observe")

    raw_request: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": _SAMPLE_TOOL, "arguments": _SAMPLE_ARGS},
    }
    direct_request = MCPRequest(**raw_request)

    async def _run() -> dict[str, dict[str, float]]:
        # warm up both paths
        for _ in range(50):
            await upstream.send(direct_request)
            await proxy.handle(raw_request)

        direct: list[float] = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            await upstream.send(direct_request)
            direct.append((time.perf_counter() - t0) * 1000.0)

        proxied: list[float] = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            await proxy.handle(raw_request)
            proxied.append((time.perf_counter() - t0) * 1000.0)

        direct_p = _percentiles(direct)
        proxied_p = _percentiles(proxied)
        overhead = {
            "p50_ms": round(proxied_p["p50_ms"] - direct_p["p50_ms"], 4),
            "p95_ms": round(proxied_p["p95_ms"] - direct_p["p95_ms"], 4),
            "mean_ms": round(proxied_p["mean_ms"] - direct_p["mean_ms"], 4),
        }
        return {"direct": direct_p, "proxied": proxied_p, "overhead": overhead}

    return asyncio.run(_run())


def _row(label: str, p: dict[str, float]) -> str:
    return (
        f"  {label:<34} p50 {p['p50_ms']:>8.4f}   "
        f"p95 {p['p95_ms']:>8.4f}   mean {p['mean_ms']:>8.4f}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="AgentMoat overhead micro-benchmark.")
    parser.add_argument("--iterations", type=int, default=5000, help="Samples per measurement.")
    args = parser.parse_args()
    n = args.iterations

    print("AgentMoat overhead micro-benchmark")
    print("=" * 72)
    impl = f"{platform.python_implementation()} {platform.python_version()}"
    print(f"{impl} on {platform.platform()}")
    print(f"iterations per measurement: {n}   (all times in milliseconds, LLM/API call excluded)")
    print("=" * 72)

    inj = bench_injection_scan(n)
    con = bench_argument_constraints(n)
    mcp = bench_mcp_proxy(n)

    print("\n(a) injection scan per message (rule mode)")
    print(_row("InjectionDetector.scan", inj))

    print("\n(b) argument-constraint check per tool call")
    print(_row("ArgumentConstraintChecker.check", con))

    print("\n(c) end-to-end MCP proxy per intercepted call (mock upstream)")
    print(_row("direct upstream call", mcp["direct"]))
    print(_row("proxied (full interception)", mcp["proxied"]))
    print(_row("AgentMoat overhead (delta)", mcp["overhead"]))

    print("\n" + "=" * 72)
    print("Note: the upstream is a zero-cost mock, so the MCP overhead delta is")
    print("AgentMoat's interception cost only, not real tool-server/transport latency.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
