"""Injection-text scenario: AgentMoat's InjectionDetector vs. deepset/prompt-injections.

Measures the *heuristic, defense-in-depth* injection detector — not the firewall.
A text is "flagged" if ``InjectionDetector.scan`` returns any match. We report
catch rate (recall on injection-labeled text) and the false-positive rate (benign
text flagged).

The rule-based path is the headline, out-of-the-box number. The embeddings path is
reported with **independent attribution** — ``caught_by_rules_only``,
``caught_by_embeddings_only``, ``caught_by_both`` — so the optional embedding pass
gets (or is denied) credit on its own merits, rather than being folded into a union
count that looks identical to the rule-based block. The maximum cosine similarity
observed across all attack items is recorded too, so a "embeddings added zero
catches" outcome is verifiable rather than merely asserted.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentmoat.engine.injection import InjectionDetector

from ..data_loaders import InjectionTextItem

# Injectable so tests can substitute a deterministic stub detector (and avoid
# downloading the embedding model). Signature: (use_embeddings: bool) -> detector.
DetectorFactory = Callable[[bool], InjectionDetector]


def _rates(caught: int, false_pos: int, n_attacks: int, n_benign: int) -> dict[str, Any]:
    return {
        "n_attacks": n_attacks,
        "n_benign": n_benign,
        "caught": caught,
        "false_positives": false_pos,
        "catch_rate": (caught / n_attacks) if n_attacks else None,
        "false_positive_rate": (false_pos / n_benign) if n_benign else None,
    }


def _evaluate_rule_based(
    items: list[InjectionTextItem], detector: InjectionDetector
) -> dict[str, Any]:
    attacks = [it for it in items if it.label == 1]
    benign = [it for it in items if it.label == 0]
    caught = sum(1 for it in attacks if detector.scan(it.text))
    false_pos = sum(1 for it in benign if detector.scan(it.text))
    return _rates(caught, false_pos, len(attacks), len(benign))


def _sources(detector: InjectionDetector, text: str) -> tuple[bool, bool]:
    """Return (rule_hit, embedding_hit) for a single text, by match provenance."""
    matches = detector.scan(text)
    rule_hit = any(m.source == "rule" for m in matches)
    emb_hit = any(m.source == "embedding" for m in matches)
    return rule_hit, emb_hit


def _evaluate_embeddings(
    items: list[InjectionTextItem], detector: InjectionDetector
) -> dict[str, Any]:
    """Evaluate the embeddings-enabled detector, attributing catches to their source."""
    attacks = [it for it in items if it.label == 1]
    benign = [it for it in items if it.label == 0]

    rules_only = embeddings_only = both = 0
    max_similarity: float | None = None
    for it in attacks:
        rule_hit, emb_hit = _sources(detector, it.text)
        if rule_hit and emb_hit:
            both += 1
        elif rule_hit:
            rules_only += 1
        elif emb_hit:
            embeddings_only += 1
        sim = detector.max_attack_similarity(it.text)
        if sim is not None:
            max_similarity = sim if max_similarity is None else max(max_similarity, sim)

    fp_rule = fp_emb = fp_combined = 0
    for it in benign:
        rule_hit, emb_hit = _sources(detector, it.text)
        if rule_hit:
            fp_rule += 1
        if emb_hit:
            fp_emb += 1
        if rule_hit or emb_hit:
            fp_combined += 1

    n_attacks = len(attacks)
    n_benign = len(benign)
    combined_caught = rules_only + embeddings_only + both
    threshold = getattr(detector, "embedding_threshold", None)
    return {
        "n_attacks": n_attacks,
        "n_benign": n_benign,
        "caught_by_rules_only": rules_only,
        "caught_by_embeddings_only": embeddings_only,
        "caught_by_both": both,
        "combined_caught": combined_caught,
        "combined_catch_rate": (combined_caught / n_attacks) if n_attacks else None,
        # Independent credit for the embedding pass: catches it made that the
        # rules missed. This is the number that must never silently mirror the
        # rule-based block.
        "embeddings_added_catches": embeddings_only,
        "max_attack_similarity": round(max_similarity, 3) if max_similarity is not None else None,
        "embedding_threshold": threshold,
        "false_positives": {
            "combined": fp_combined,
            "by_rule": fp_rule,
            "by_embedding": fp_emb,
            "false_positive_rate": (fp_combined / n_benign) if n_benign else None,
        },
    }


def run(
    items: list[InjectionTextItem],
    include_embeddings: bool = False,
    detector_factory: DetectorFactory = InjectionDetector,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "dataset": "deepset/prompt-injections",
        "rule_based": _evaluate_rule_based(items, detector_factory(False)),
    }
    if include_embeddings:
        result["embeddings"] = _evaluate_embeddings(items, detector_factory(True))
    return result
