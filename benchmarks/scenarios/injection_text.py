"""Injection-text scenario: AgentMoat's InjectionDetector vs. deepset/prompt-injections.

Measures the *heuristic, defense-in-depth* injection detector — not the firewall.
A text is "flagged" if ``InjectionDetector.scan`` returns any match. We report
catch rate (recall on injection-labeled text) and the false-positive rate (benign
text flagged), separately for the deterministic rule-based path (the headline,
out-of-the-box number) and the optional embeddings path.
"""

from __future__ import annotations

from typing import Any

from agentmoat.engine.injection import InjectionDetector

from ..data_loaders import InjectionTextItem


def _evaluate(items: list[InjectionTextItem], use_embeddings: bool) -> dict[str, Any]:
    detector = InjectionDetector(use_embeddings=use_embeddings)

    attacks = [it for it in items if it.label == 1]
    benign = [it for it in items if it.label == 0]

    caught = sum(1 for it in attacks if detector.scan(it.text))
    false_pos = sum(1 for it in benign if detector.scan(it.text))

    n_attacks = len(attacks)
    n_benign = len(benign)
    return {
        "n_attacks": n_attacks,
        "n_benign": n_benign,
        "caught": caught,
        "false_positives": false_pos,
        "catch_rate": (caught / n_attacks) if n_attacks else None,
        "false_positive_rate": (false_pos / n_benign) if n_benign else None,
    }


def run(items: list[InjectionTextItem], include_embeddings: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "dataset": "deepset/prompt-injections",
        "rule_based": _evaluate(items, use_embeddings=False),
    }
    if include_embeddings:
        result["embeddings"] = _evaluate(items, use_embeddings=True)
    return result
