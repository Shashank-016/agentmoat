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

# Maps a text to an ISO-639-1 language code ("en", "de", ...) or "unknown".
LanguageDetector = Callable[[str], str]

_LANGDETECT_SEEDED = False


def _detect_language(text: str) -> str:
    """Detect a text's language via ``langdetect`` (optional benchmark dep).

    Returns an ISO-639-1 code, or ``"unknown"`` when langdetect is not installed
    or cannot classify the text. Seeds langdetect once for reproducibility.
    """
    global _LANGDETECT_SEEDED
    try:
        from langdetect import DetectorFactory as _LDFactory
        from langdetect import detect

        if not _LANGDETECT_SEEDED:
            _LDFactory.seed = 0
            _LANGDETECT_SEEDED = True
        return detect(text)
    except Exception:
        return "unknown"


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


def _evaluate_by_language(
    items: list[InjectionTextItem],
    detector: InjectionDetector,
    lang_detector: LanguageDetector,
) -> dict[str, Any]:
    """Split rule-based catch rate and FPR by detected language.

    The deepset corpus is heavily multilingual and the rule patterns are
    English-only, so a single headline catch rate conflates "missed an English
    attack" with "the language isn't covered at all". This breaks it out.
    """
    # lang -> mutable tallies
    tallies: dict[str, dict[str, int]] = {}
    for it in items:
        lang = lang_detector(it.text)
        t = tallies.setdefault(lang, {"attacks": 0, "benign": 0, "caught": 0, "false_pos": 0})
        hit = bool(detector.scan(it.text))
        if it.label == 1:
            t["attacks"] += 1
            if hit:
                t["caught"] += 1
        else:
            t["benign"] += 1
            if hit:
                t["false_pos"] += 1

    # Per-language block, ordered by sample count (most-represented first).
    by_language: dict[str, Any] = {}
    for lang, t in sorted(tallies.items(), key=lambda kv: -(kv[1]["attacks"] + kv[1]["benign"])):
        by_language[lang] = _rates(t["caught"], t["false_pos"], t["attacks"], t["benign"])

    # English vs. non-English aggregate. "unknown" (unclassifiable) is grouped
    # with non-English, since it is by definition not confidently English.
    def _agg(langs: list[str]) -> dict[str, Any]:
        caught = sum(tallies[x]["caught"] for x in langs)
        fp = sum(tallies[x]["false_pos"] for x in langs)
        na = sum(tallies[x]["attacks"] for x in langs)
        nb = sum(tallies[x]["benign"] for x in langs)
        return _rates(caught, fp, na, nb)

    english = [x for x in tallies if x == "en"]
    non_english = [x for x in tallies if x != "en"]
    return {
        "by_language": by_language,
        "english_vs_non_english": {
            "english": _agg(english),
            "non_english": _agg(non_english),
        },
    }


def run(
    items: list[InjectionTextItem],
    include_embeddings: bool = False,
    detector_factory: DetectorFactory = InjectionDetector,
    lang_detector: LanguageDetector = _detect_language,
) -> dict[str, Any]:
    rule_detector = detector_factory(False)
    rule_based = _evaluate_rule_based(items, rule_detector)
    rule_based.update(_evaluate_by_language(items, rule_detector, lang_detector))
    result: dict[str, Any] = {
        "dataset": "deepset/prompt-injections",
        "rule_based": rule_based,
    }
    if include_embeddings:
        result["embeddings"] = _evaluate_embeddings(items, detector_factory(True))
    return result
