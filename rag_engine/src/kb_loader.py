"""
Loads KB records in Person 1's REAL locked schema (kb-master-v1.0-frozen),
as defined in kb_master/schema.json and confirmed against the real
T1190.json record on Day 3.

Real schema, not the earlier placeholder guess:
  technique_record: id, tactic, technique_name, description,
                     detection_signatures (dual-source object: log_tail / falco),
                     related_cves (list of CVE ID strings), mitigation,
                     + optional scenario_refs, is_scenario_critical,
                       sub_technique_of, platforms, data_sources
  cve_record:       cve_id, description, cvss_score, affected_component,
                     related_technique_ids, lab_planted,
                     + optional cwe_ids, cvss_vector, published_date,
                       scenario_refs, patch_reference

Two record types, linked by ID (technique.related_cves <-> cve.related_technique_ids),
not one flat KB record like the earlier placeholder assumed.

Swap-in for Day 3: point TECHNIQUES_DIR / CVES_DIR at the real
kb_master/techniques/ and kb_master/cves/ directories (36 + 16 files).
Never edit those directories in place -- load_kb_dir() only reads them.
"""
from __future__ import annotations
import glob
import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any


@dataclass
class DetectionSignature:
    log_tail: Optional[Dict[str, Any]] = None
    falco: Optional[Dict[str, Any]] = None

    @property
    def sources(self) -> List[str]:
        """Which detector source(s) this technique is observable through."""
        out = []
        if self.log_tail is not None:
            out.append("log_tail")
        if self.falco is not None:
            out.append("falco")
        return out

    def to_text(self) -> str:
        parts = []
        if self.log_tail:
            parts.append(
                f"log_tail event {self.log_tail.get('event_type', '')}: "
                f"{self.log_tail.get('pattern', '')}"
            )
        if self.falco:
            parts.append(
                f"falco rule {self.falco.get('rule_name', '')}: "
                f"{self.falco.get('trigger_condition', '')}"
            )
        return " ".join(parts)


@dataclass
class KBRecord:
    """A technique record. Field names match kb_master/schema.json exactly."""
    id: str
    tactic: str
    technique_name: str
    description: str
    detection_signatures: DetectionSignature
    related_cves: List[str] = field(default_factory=list)
    mitigation: str = ""
    scenario_refs: List[str] = field(default_factory=list)
    is_scenario_critical: bool = False
    sub_technique_of: Optional[str] = None
    platforms: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)

    def to_text(self) -> str:
        """Flattened text used for embedding. Keep in one place so Layer1/Layer2/flat-RAG stay consistent."""
        sig_text = self.detection_signatures.to_text()
        cves = " ".join(self.related_cves)
        return (
            f"{self.technique_name}. {self.description} "
            f"Signatures: {sig_text} CVEs: {cves} Mitigation: {self.mitigation}"
        )

    def tactic_summary_text(self) -> str:
        """Used for Layer 1 (tactic-level) retrieval.

        BUGFIX: this previously omitted detection_signatures entirely, even
        though that's the part of the record most likely to share vocabulary
        with a raw alert (event_type / pattern / falco rule text -- see
        DetectionSignature.to_text()). to_text() below deliberately includes
        it for exactly that reason ("Keep in one place so Layer1/Layer2/
        flat-RAG stay consistent"), but tactic_summary_text() wasn't
        actually using it, so Layer 1's tactic-level aggregate documents
        were starved of the one signal that reliably ties an alert to a
        technique. That's why two-layer scored far below flat-RAG (which
        embeds the full to_text() per record): Layer 1 picked the wrong
        tactic more often than not, so Layer 2 was searching within the
        wrong candidate pool before it ever got a chance.
        """
        sig_text = self.detection_signatures.to_text()
        return f"{self.tactic}: {self.technique_name}. {self.description} Signatures: {sig_text}"


@dataclass
class CVERecord:
    """A CVE record. Field names match kb_master/schema.json's cve_record exactly."""
    cve_id: str
    description: str
    cvss_score: float
    affected_component: str
    related_technique_ids: List[str] = field(default_factory=list)
    lab_planted: bool = False
    cwe_ids: List[str] = field(default_factory=list)
    cvss_vector: str = ""
    published_date: str = ""
    scenario_refs: List[str] = field(default_factory=list)
    patch_reference: str = ""


def _parse_technique(r: dict) -> KBRecord:
    sig_raw = r.get("detection_signatures", {}) or {}
    return KBRecord(
        id=r["id"],
        tactic=r["tactic"],
        technique_name=r["technique_name"],
        description=r["description"],
        detection_signatures=DetectionSignature(
            log_tail=sig_raw.get("log_tail"),
            falco=sig_raw.get("falco"),
        ),
        related_cves=r.get("related_cves", []),
        mitigation=r.get("mitigation", ""),
        scenario_refs=r.get("scenario_refs", []),
        is_scenario_critical=r.get("is_scenario_critical", False),
        sub_technique_of=r.get("sub_technique_of"),
        platforms=r.get("platforms", []),
        data_sources=r.get("data_sources", []),
    )


def _parse_cve(r: dict) -> CVERecord:
    return CVERecord(
        cve_id=r["cve_id"],
        description=r["description"],
        cvss_score=r["cvss_score"],
        affected_component=r["affected_component"],
        related_technique_ids=r.get("related_technique_ids", []),
        lab_planted=r.get("lab_planted", False),
        cwe_ids=r.get("cwe_ids", []),
        cvss_vector=r.get("cvss_vector", ""),
        published_date=r.get("published_date", ""),
        scenario_refs=r.get("scenario_refs", []),
        patch_reference=r.get("patch_reference", ""),
    )


def load_kb_dir(techniques_dir: str, cves_dir: Optional[str] = None) -> tuple[List[KBRecord], List[CVERecord]]:
    """
    Loads from a directory of per-record JSON files, matching Person 1's
    real kb_master/ layout (kb_master/techniques/*.json, kb_master/cves/*.json).
    """
    techniques = []
    for path in sorted(glob.glob(os.path.join(techniques_dir, "*.json"))):
        with open(path) as f:
            techniques.append(_parse_technique(json.load(f)))

    cves = []
    if cves_dir and os.path.isdir(cves_dir):
        for path in sorted(glob.glob(os.path.join(cves_dir, "*.json"))):
            with open(path) as f:
                cves.append(_parse_cve(json.load(f)))

    return techniques, cves


def load_kb_combined_json(path: str) -> tuple[List[KBRecord], List[CVERecord]]:
    """
    Loads from a single combined JSON file shaped like:
      {"techniques": [...], "cves": [...]}
    Useful for the placeholder fixture and for any export Person 1 hands
    over as one file instead of a directory tree.
    """
    with open(path) as f:
        raw = json.load(f)
    techniques = [_parse_technique(r) for r in raw.get("techniques", [])]
    cves = [_parse_cve(r) for r in raw.get("cves", [])]
    return techniques, cves


def tactic_summaries(records: List[KBRecord]) -> Dict[str, str]:
    """Aggregate one summary string per unique tactic, for Layer 1 retrieval."""
    by_tactic: Dict[str, List[str]] = {}
    for r in records:
        by_tactic.setdefault(r.tactic, []).append(r.tactic_summary_text())
    return {tactic: " ".join(texts) for tactic, texts in by_tactic.items()}


def cve_lookup(cves: List[CVERecord]) -> Dict[str, CVERecord]:
    """cve_id -> CVERecord, for joining technique.related_cves at query time."""
    return {c.cve_id: c for c in cves}
