"""Argument-firewall scenario: AgentMoat's policy + constraint checks vs. AgentDojo.

This is the core ("moat") benchmark. For each AgentDojo user task we derive a
least-privilege policy from its *benign* ground-truth tool sequence (allow exactly
those tools, deny the rest), then measure what that policy — plus AgentMoat's
always-on argument constraints — happens to block on the paired indirect-injection
tasks. The policy is never tuned to the attacks.

An attack case is "caught" if any of its tool calls is blocked, either because:
  * the attack needs a tool outside the user task's least-privilege allow-list
    (``by_policy``), or
  * a tool call's arguments trip an always-on constraint — path traversal, SSRF,
    sensitive path, shell metacharacters (``by_constraint``).

False positives are measured on the benign ground-truth calls under the same
policy. Policy-level FPR is 0 by construction (the policy allows the benign tools
by definition), so the reported firewall FPR isolates the *always-on argument
constraints* firing on legitimate tool-call arguments.
"""

from __future__ import annotations

from typing import Any

from agentmoat.engine.policy import ToolPolicyEngine

from ..data_loaders import AgentDojoData


def run(data: AgentDojoData, policy_path: str) -> dict[str, Any]:
    engine = ToolPolicyEngine(policy_path=policy_path)

    # --- Catch rate over security (user_task x injection_task) cases ---
    n_cases = len(data.security_cases)
    caught = 0
    caught_by_policy = 0
    caught_by_constraint = 0

    for case in data.security_cases:
        blocked = False
        by_policy = False
        by_constraint = False
        for call in case.attack_calls:
            if not engine.check(case.agent_id, call.tool).allowed:
                blocked = True
                by_policy = True
            if engine.check_arguments(case.agent_id, call.tool, call.args):
                blocked = True
                by_constraint = True
        if blocked:
            caught += 1
        if by_policy:
            caught_by_policy += 1
        if by_constraint:
            caught_by_constraint += 1

    # --- False positives over benign ground-truth calls ---
    n_benign_calls = 0
    benign_blocked = 0
    benign_blocked_by_policy = 0
    benign_blocked_by_constraint = 0

    for ut in data.user_tasks:
        for call in ut.benign_calls:
            n_benign_calls += 1
            policy_block = not engine.check(ut.agent_id, call.tool).allowed
            constraint_block = bool(engine.check_arguments(ut.agent_id, call.tool, call.args))
            if policy_block:
                benign_blocked_by_policy += 1
            if constraint_block:
                benign_blocked_by_constraint += 1
            if policy_block or constraint_block:
                benign_blocked += 1

    return {
        "dataset": "agentdojo",
        "n_user_tasks": len(data.user_tasks),
        "n_security_cases": n_cases,
        "excluded_user_tasks": len(data.excluded_user_tasks),
        "excluded_injection_tasks": len(data.excluded_injection_tasks),
        "catch": {
            "caught": caught,
            "catch_rate": (caught / n_cases) if n_cases else None,
            "caught_by_policy": caught_by_policy,
            "caught_by_constraint": caught_by_constraint,
        },
        "false_positives": {
            "n_benign_calls": n_benign_calls,
            "blocked": benign_blocked,
            "false_positive_rate": (benign_blocked / n_benign_calls) if n_benign_calls else None,
            "blocked_by_policy": benign_blocked_by_policy,
            "blocked_by_constraint": benign_blocked_by_constraint,
        },
    }
