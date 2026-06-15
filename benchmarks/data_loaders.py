"""Dataset loaders for the AgentMoat benchmark.

Two public, externally-sourced datasets are used:

* **deepset/prompt-injections** (HuggingFace, Apache-2.0, ungated) — labeled
  prompt-injection vs. benign text, for the injection-text detector scenario.
* **AgentDojo** (ethz-spylab/agentdojo, MIT) — tool-calling agent tasks with
  benign ground-truth tool sequences and paired indirect-injection tasks, for
  the argument-firewall scenario.

Nothing is vendored into the repo: both are downloaded at run time (and cached
by their respective libraries) so the benchmark always reflects the upstream
data. See ``benchmarks/README.md`` for licensing and caveats.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Injection-text dataset (deepset/prompt-injections)
# ---------------------------------------------------------------------------

DEEPSET_DATASET = "deepset/prompt-injections"


@dataclass
class InjectionTextItem:
    text: str
    label: int  # 1 = injection, 0 = benign


def load_injection_text(limit: int | None = None) -> list[InjectionTextItem]:
    """Load deepset/prompt-injections (train + test splits combined).

    Requires the ``datasets`` library (see ``benchmarks/requirements.txt``).
    """
    from datasets import load_dataset  # local import: optional benchmark dep

    items: list[InjectionTextItem] = []
    ds = load_dataset(DEEPSET_DATASET)
    for split in ds:
        for row in ds[split]:
            text = row.get("text")
            label = row.get("label")
            if text is None or label is None:
                continue
            items.append(InjectionTextItem(text=str(text), label=int(label)))
    if limit is not None:
        items = items[:limit]
    return items


# ---------------------------------------------------------------------------
# Tool-call dataset (AgentDojo)
# ---------------------------------------------------------------------------

AGENTDOJO_VERSION = "v1"


@dataclass
class ToolCall:
    tool: str
    args: dict[str, Any]


@dataclass
class UserTaskCase:
    """A benign AgentDojo user task and the least-privilege policy derived from it."""

    suite: str
    task_id: str
    agent_id: str
    allowed_tools: list[str]
    benign_calls: list[ToolCall]


@dataclass
class SecurityCase:
    """An injection task evaluated in the context (policy) of a user task."""

    suite: str
    user_task_id: str
    injection_task_id: str
    agent_id: str  # the user task's least-privilege agent
    attack_calls: list[ToolCall]


@dataclass
class AgentDojoData:
    user_tasks: list[UserTaskCase] = field(default_factory=list)
    security_cases: list[SecurityCase] = field(default_factory=list)
    # Tasks whose ground_truth could not be enumerated (e.g. not implemented).
    excluded_user_tasks: list[str] = field(default_factory=list)
    excluded_injection_tasks: list[str] = field(default_factory=list)

    def derived_policy(self) -> dict[str, Any]:
        """Build the exact least-privilege policy dict used by the firewall scenario.

        For every user task, ``allowed_tools`` is precisely the set of tools its
        *benign* ground-truth sequence uses; everything else is implicitly
        denied by AgentMoat's allow-list semantics. This is derived purely from
        benign behaviour — never from the attack set — so it is not tuned to the
        test cases it is later measured against.
        """
        agents: dict[str, Any] = {}
        for ut in self.user_tasks:
            agents[ut.agent_id] = {"allowed_tools": ut.allowed_tools, "denied_tools": []}
        return {"version": "1", "agents": agents}


def _agent_id(suite: str, user_task_id: str) -> str:
    return f"{suite}__{user_task_id}"


def _calls_from_ground_truth(gt: Any) -> list[ToolCall]:
    calls: list[ToolCall] = []
    for fc in gt:
        name = getattr(fc, "function", None)
        args = getattr(fc, "args", None) or {}
        if name:
            calls.append(ToolCall(tool=str(name), args=dict(args)))
    return calls


def load_agentdojo() -> AgentDojoData:
    """Enumerate AgentDojo benign tasks + paired injection tasks statically.

    No LLM is run: we read each task's declared ground-truth ``FunctionCall``
    sequence directly. Each suite's injection tasks are paired with every user
    task in that suite (matching AgentDojo's own security-case construction),
    and each pairing is evaluated under that *user task's* least-privilege
    policy.
    """
    from agentdojo.task_suite.load_suites import get_suites

    data = AgentDojoData()
    suites = get_suites(AGENTDOJO_VERSION)

    for suite_name, suite in suites.items():
        env = suite.load_and_inject_default_environment({})

        # Benign user tasks → least-privilege policy.
        ut_tools: dict[str, list[str]] = {}
        for ut_id, ut in suite.user_tasks.items():
            try:
                gt = ut.ground_truth(env)
            except Exception:
                data.excluded_user_tasks.append(_agent_id(suite_name, ut_id))
                continue
            calls = _calls_from_ground_truth(gt)
            if not calls:
                data.excluded_user_tasks.append(_agent_id(suite_name, ut_id))
                continue
            allowed = sorted({c.tool for c in calls})
            ut_tools[ut_id] = allowed
            data.user_tasks.append(
                UserTaskCase(
                    suite=suite_name,
                    task_id=ut_id,
                    agent_id=_agent_id(suite_name, ut_id),
                    allowed_tools=allowed,
                    benign_calls=calls,
                )
            )

        # Injection tasks → attack tool calls, paired with each valid user task.
        for it_id, it in suite.injection_tasks.items():
            try:
                igt = it.ground_truth(env)
            except Exception:
                data.excluded_injection_tasks.append(f"{suite_name}__{it_id}")
                continue
            attack_calls = _calls_from_ground_truth(igt)
            if not attack_calls:
                data.excluded_injection_tasks.append(f"{suite_name}__{it_id}")
                continue
            for ut_id in ut_tools:
                data.security_cases.append(
                    SecurityCase(
                        suite=suite_name,
                        user_task_id=ut_id,
                        injection_task_id=it_id,
                        agent_id=_agent_id(suite_name, ut_id),
                        attack_calls=attack_calls,
                    )
                )

    return data
