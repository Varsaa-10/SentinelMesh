"""
Module B3 — Person 3, Day 4: poison-detection scoring logic.

Two complementary detection layers, matched to which poisoning types they
can actually catch (being honest that no single method catches all 5):

1. STATIC KB INTEGRITY CHECKS (scan_kb) -- inspect the KB content itself,
   no retrieval needed. Catches:
     - Variant 1 (mislabeled CVE mapping)  -> bidirectional link check
     - Variant 2 (injected fake entry)     -> ATT&CK ID pattern + allowlist check
     - Variant 5 (stale/contradictory)     -> keyword heuristic on mitigation text
   Cannot catch variants 3/4 -- their id/tactic/technique_name are all
   valid and consistent; only the DESCRIPTION text is wrong, which static
   checks have no ground truth to compare against.

2. RETRIEVAL-TIME SUSPICION SCORE (score_retrieval_result) -- reuses the
   confidence components already computed by rag_engine.py's
   TwoLayerRAG/FlatRAG (similarity, source_agreement, cross_document_
   agreement, retrieval_consistency). Catches:
     - Variant 3 (near-duplicate wrong label) -> often flagged: high
       similarity but the winning record's declared detection source may
       not match the alert's real source (T1078's real detection is
       log_tail; T1110 corrupted-with-T1078-text is also log_tail here,
       so this one is NOT reliably caught by source_agreement -- see
       evaluate_poisoning.py's real results, not a hopeful claim)
     - Variant 4 (adversarial embedding) -> often flagged: the hijacking
       record's real tactic/source usually doesn't match the alert's
       true source, producing a source_agreement/cross_document_agreement
       mismatch even when text similarity is artificially high
   Cannot reliably catch variant 5 -- retrieval still finds the CORRECT
   record (T1212), so similarity/agreement/consistency all look fine;
   only the payload (mitigation text) is wrong, which retrieval-time
   scoring has no visibility into at all.

This split is reported explicitly rather than claiming one unified
detector catches everything -- it doesn't, and pretending otherwise would
misrepresent what Week 3's poisoning-runs evaluation should expect.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List, Dict, Optional

# The known-real ATT&CK-style IDs this KB is supposed to contain, per
# Person 1's changelog (36 techniques). Used for the fake-entry allowlist
# check in variant 2. Anything NOT in this set is suspicious.
KNOWN_REAL_TECHNIQUE_IDS = {
    "T1003.008", "T1003", "T1021", "T1027", "T1029", "T1036", "T1041", "T1048",
    "T1053.003", "T1059", "T1068", "T1070", "T1078", "T1080", "T1082", "T1083",
    "T1087", "T1098", "T1110", "T1133", "T1136", "T1190", "T1195", "T1212",
    "T1485", "T1499", "T1528", "T1534", "T1539", "T1550", "T1552", "T1553",
    "T1555", "T1562", "T1563", "T1566",
}

ATTACK_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")

# Heuristic phrases that indicate stale/contradictory mitigation guidance --
# a real mitigation should never say a known vulnerability is low-risk,
# doesn't need patching, or is acceptable to ignore.
CONTRADICTORY_PHRASES = [
    "does not require patching", "does not need to be patched",
    "low-risk", "low risk", "can be accepted as a known limitation",
    "no patching required", "is secure by default", "not vulnerable",
    "considered safe", "no need to", "not a real threat",
]


@dataclass
class IntegrityFinding:
    severity: str  # "high" | "medium"
    record_type: str  # "technique" | "cve"
    record_id: str
    finding: str


def scan_kb(techniques: list, cves: list) -> List[IntegrityFinding]:
    """
    Static, retrieval-free scan. techniques/cves are KBRecord/CVERecord
    lists from kb_loader.load_kb_dir() -- run this against a candidate
    KB variant BEFORE ever querying it.
    """
    findings: List[IntegrityFinding] = []
    cve_by_id = {c.cve_id: c for c in cves}
    tech_by_id = {t.id: t for t in techniques}

    # --- Catches variant 2: injected fake entries ---
    for t in techniques:
        if not ATTACK_ID_PATTERN.match(t.id):
            findings.append(IntegrityFinding(
                "high", "technique", t.id,
                f"ID '{t.id}' does not match the standard ATT&CK ID pattern (T####[.###])."
            ))
        elif t.id not in KNOWN_REAL_TECHNIQUE_IDS:
            findings.append(IntegrityFinding(
                "high", "technique", t.id,
                f"ID '{t.id}' matches ATT&CK ID formatting but is not in the known-real "
                f"technique allowlist for this KB -- possible fabricated entry."
            ))

    # --- Catches variant 1: mislabeled/asymmetric technique<->CVE links ---
    for t in techniques:
        for cve_id in t.related_cves:
            cve = cve_by_id.get(cve_id)
            if cve is None:
                findings.append(IntegrityFinding(
                    "medium", "technique", t.id,
                    f"References CVE '{cve_id}' which does not exist in the CVE record set."
                ))
            elif t.id not in cve.related_technique_ids:
                findings.append(IntegrityFinding(
                    "high", "technique", t.id,
                    f"Lists related_cves=['{cve_id}'] but that CVE's related_technique_ids "
                    f"does not list '{t.id}' back -- asymmetric/broken bidirectional link."
                ))
    for c in cves:
        for tech_id in c.related_technique_ids:
            tech = tech_by_id.get(tech_id)
            if tech is None:
                findings.append(IntegrityFinding(
                    "medium", "cve", c.cve_id,
                    f"References technique '{tech_id}' which does not exist in the technique record set."
                ))
            elif c.cve_id not in tech.related_cves:
                findings.append(IntegrityFinding(
                    "high", "cve", c.cve_id,
                    f"Lists related_technique_ids=['{tech_id}'] but that technique's "
                    f"related_cves does not list '{c.cve_id}' back -- asymmetric/broken bidirectional link."
                ))

    # --- Catches variant 5: stale/contradictory mitigation guidance ---
    for t in techniques:
        mitigation_lower = t.mitigation.lower()
        for phrase in CONTRADICTORY_PHRASES:
            if phrase in mitigation_lower:
                findings.append(IntegrityFinding(
                    "high", "technique", t.id,
                    f"Mitigation text contains suspicious phrase '{phrase}' -- "
                    f"possible stale/contradictory guidance."
                ))
                break  # one flag per record is enough

    # --- Catches variant 3: near-duplicate descriptions across different IDs ---
    findings.extend(find_duplicate_descriptions(techniques))

    return findings


def _word_set(text: str) -> set:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def find_duplicate_descriptions(techniques: list, similarity_threshold: float = 0.55) -> List[IntegrityFinding]:
    """
    Catches variant 3 (near-duplicate with wrong label): a static,
    retrieval-free pairwise comparison of every technique's description
    against every other's. Two DIFFERENT technique IDs with suspiciously
    similar description text is exactly the signature of a copied/stolen
    description, regardless of whether their detection_signatures still
    look internally consistent (which is precisely why the retrieval-time
    source_agreement check misses this case -- see score_retrieval_result's
    docstring).

    This does NOT catch variant 4 (adversarial embedding) reliably --
    that attack borrows vocabulary/phrases rather than copying a whole
    description, so pairwise whole-description similarity stays below
    threshold. Confirmed empirically in evaluate_poisoning.py's results,
    not assumed.
    """
    findings: List[IntegrityFinding] = []
    seen_pairs = set()
    word_sets = {t.id: _word_set(t.description) for t in techniques}
    ids = list(word_sets.keys())

    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            id_a, id_b = ids[i], ids[j]
            sim = _jaccard(word_sets[id_a], word_sets[id_b])
            if sim >= similarity_threshold:
                pair_key = tuple(sorted([id_a, id_b]))
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)
                findings.append(IntegrityFinding(
                    "high", "technique", f"{id_a} / {id_b}",
                    f"Descriptions for {id_a} and {id_b} are {sim:.0%} word-overlap "
                    f"similar despite being different technique IDs -- likely a "
                    f"copied/near-duplicate description (one of them may carry a "
                    f"wrong label)."
                ))
    return findings


@dataclass
class RetrievalSuspicion:
    is_suspect: bool
    reason: str
    similarity: float
    source_agreement: float
    cross_document_agreement: float


def score_retrieval_result(rag_result, similarity_threshold: float = 0.4,
                            min_similarity_threshold: float = 0.25,
                            source_agreement_threshold: float = 0.4) -> RetrievalSuspicion:
    """
    rag_result: a RAGResult from rag_engine.py / flat_rag.py's .query().
    Flags "high similarity but source mismatch" or "weak absolute similarity" --
    the signature of an adversarial/mislabeled record winning on vocabulary
    alone or failing to match any legitimate KB entry cleanly.
    """
    c = rag_result.confidence
    sim = c.similarity
    src = c.source_agreement
    agree = c.cross_document_agreement

    # 1. Absolute low similarity check (weak top match is suspicious)
    if sim < min_similarity_threshold:
        return RetrievalSuspicion(
            True,
            f"Low absolute similarity score ({sim:.2f} < {min_similarity_threshold}) -- "
            f"alert failed to match any legitimate KB technique cleanly (possible unknown or poisoned query).",
            sim, src, agree,
        )

    # 2. Source & Detection Signature mismatch check
    if sim >= similarity_threshold and src <= source_agreement_threshold:
        return RetrievalSuspicion(
            True,
            f"High text similarity ({sim:.2f}) but the winning record's declared "
            f"detection signature doesn't match this alert's source ({src:.2f}) -- "
            f"possible adversarial/mislabeled entry.",
            sim, src, agree,
        )

    return RetrievalSuspicion(False, "No suspicion flags triggered.", sim, src, agree)
