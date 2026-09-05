"""
Module B3 — Person 3 (Poisoned KB Variants & Detection), Day 1-3.

Builds 5 distinct poisoned copies of the KB, each a FULL copy of
kb_master_real/ with exactly one corruption type applied. NEVER modifies
kb_master_real/ itself -- reads it read-only, writes to
poisoning/variants/variant_N_*/, matching the plan's requirement that the
master copy is never touched and every poisoned variant is a separate,
clearly labeled copy.

The 5 poisoning types (per the execution plan, Week 2 Module B3):
  1. Mislabeled technique-CVE mapping
  2. Injected fake entry
  3. Semantic near-duplicate with wrong label
  4. Adversarial embedding (text crafted to hijack retrieval for another technique)
  5. Stale/contradictory entry
"""
import json
import os
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTER_TECH = os.path.join(ROOT, "kb", "kb_master_real", "techniques")
MASTER_CVE = os.path.join(ROOT, "kb", "kb_master_real", "cves")
VARIANTS_DIR = os.path.join(ROOT, "poisoning", "variants")


def copy_master_into(variant_dir: str) -> None:
    """Full copy of the real master KB into a fresh variant directory."""
    tech_dir = os.path.join(variant_dir, "techniques")
    cve_dir = os.path.join(variant_dir, "cves")
    if os.path.exists(variant_dir):
        shutil.rmtree(variant_dir)
    shutil.copytree(MASTER_TECH, tech_dir)
    shutil.copytree(MASTER_CVE, cve_dir)


def load_json(path):
    with open(path) as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# --- Variant 1: Mislabeled technique-CVE mapping ---
def build_variant_1():
    """
    Corrupt CVE-2022-29217's related_technique_ids to point at an unrelated
    technique (T1499, Endpoint DoS -- different tactic entirely, Impact vs.
    Credential Access). The technique side (T1212.json) is left untouched,
    so the mapping becomes asymmetric/inconsistent -- T1212 still lists
    CVE-2022-29217 in related_cves, but the CVE no longer lists T1212 back.
    This is exactly the kind of bidirectional-link integrity break a real
    poisoning attack would introduce.
    """
    variant_dir = os.path.join(VARIANTS_DIR, "variant_1_mislabeled_cve")
    copy_master_into(variant_dir)
    cve_path = os.path.join(variant_dir, "cves", "CVE-2022-29217.json")
    cve = load_json(cve_path)
    cve["_poison_note"] = (
        "POISONED (variant 1: mislabeled technique-CVE mapping). "
        "related_technique_ids changed from ['T1212'] to ['T1499'] -- "
        "an unrelated technique in a different tactic (Impact, not "
        "Credential Access). The technique side (T1212.json) still lists "
        "this CVE, creating a detectable one-way link break."
    )
    cve["related_technique_ids"] = ["T1499"]
    save_json(cve_path, cve)
    print(f"[variant 1] CVE-2022-29217.related_technique_ids: ['T1212'] -> ['T1499']")


# --- Variant 2: Injected fake entry ---
def build_variant_2():
    """
    Inject a fabricated technique record with a fake, non-existent ATT&CK
    ID that mimics real formatting well enough to blend in on casual
    inspection, but does not correspond to any real technique.
    """
    variant_dir = os.path.join(VARIANTS_DIR, "variant_2_fake_entry")
    copy_master_into(variant_dir)
    fake = {
        "_poison_note": (
            "POISONED (variant 2: injected fake entry). This entire record "
            "is fabricated -- T1337.007 is not a real MITRE ATT&CK "
            "technique ID. It is designed to look plausible (correct "
            "field shape, dotted sub-technique ID format, ATT&CK-style "
            "prose) to blend in against casual inspection."
        ),
        "id": "T1337.007",
        "tactic": "Privilege Escalation",
        "technique_name": "Shared Memory Segment Injection",
        "description": "Adversaries may inject malicious code into a shared memory segment (SHM) exposed between containers on the same host, exploiting improperly scoped IPC namespaces to escalate privileges across container boundaries without crossing the network stack.",
        "detection_signatures": {
            "log_tail": None,
            "falco": {
                "rule_name": "SentinelMesh Shared Memory Anomaly",
                "rule_file": "detection/falco-rules/fabricated_shm.yaml",
                "trigger_condition": "a process attaches to a shared memory segment owned by a different container's namespace"
            }
        },
        "related_cves": [],
        "mitigation": "Isolate IPC namespaces per container, disable shared memory access between unrelated containers.",
        "scenario_refs": [],
        "is_scenario_critical": False,
        "sub_technique_of": "T1337",
        "platforms": ["Linux", "Containers"],
        "data_sources": ["Process: OS API Execution"]
    }
    save_json(os.path.join(variant_dir, "techniques", "T1337.007.json"), fake)
    print(f"[variant 2] Injected fabricated record T1337.007.json (not a real ATT&CK ID)")


# --- Variant 3: Semantic near-duplicate with wrong label ---
def build_variant_3():
    """
    Overwrite T1110.json's description with T1078's real description
    (near-verbatim), while KEEPING T1110's id/tactic/technique_name. This
    creates a record whose metadata says "Brute Force / Credential Access"
    but whose text is actually about "Valid Accounts / default creds" --
    designed so retrieval matches on text similarity but returns the
    wrong technique ID and tactic.
    """
    variant_dir = os.path.join(VARIANTS_DIR, "variant_3_near_duplicate")
    copy_master_into(variant_dir)
    t1078 = load_json(os.path.join(variant_dir, "techniques", "T1078.json"))
    t1110_path = os.path.join(variant_dir, "techniques", "T1110.json")
    t1110 = load_json(t1110_path)

    t1110["_poison_note"] = (
        "POISONED (variant 3: semantic near-duplicate with wrong label). "
        "The description below is copied near-verbatim from the REAL "
        "T1078.json (Valid Accounts), but this record still declares "
        "id=T1110, tactic=Credential Access, technique_name=Brute Force. "
        "A query that should match T1078 will likely retrieve this record "
        "instead, and return the wrong technique ID."
    )
    t1110["description"] = t1078["description"]
    save_json(t1110_path, t1110)
    print(f"[variant 3] T1110.json's description replaced with T1078's (id/tactic/name unchanged)")


# --- Variant 4: Adversarial embedding ---
def build_variant_4():
    """
    Corrupt a distractor technique (T1566, Phishing) by stuffing its
    description with vocabulary lifted from T1190's real description
    (SQL injection / webapp / login endpoint terms), while keeping
    T1566's own id/tactic/technique_name. This is an adversarial-text
    attack: designed to hijack retrieval for SQLi-related alerts toward
    an unrelated technique, purely via engineered text similarity.
    """
    variant_dir = os.path.join(VARIANTS_DIR, "variant_4_adversarial_embedding")
    copy_master_into(variant_dir)
    path = os.path.join(variant_dir, "techniques", "T1566.json")
    record = load_json(path)
    record["_poison_note"] = (
        "POISONED (variant 4: adversarial embedding). The description "
        "below is engineered to be lexically close to T1190's real "
        "description (SQL injection / webapp / login vocabulary stuffed "
        "in), while id/tactic/technique_name still say Phishing / Initial "
        "Access. This targets TF-IDF-style retrieval specifically -- a "
        "query about SQL injection in a login endpoint may retrieve this "
        "record instead of the real T1190."
    )
    record["description"] = (
        "Adversaries may send phishing messages that reference a webapp login endpoint "
        "vulnerable to SQL injection, a weakness in an Internet-facing host where a raw "
        "SQL string concatenation vulnerability in the login endpoint allows an attacker "
        "to inject SQL payloads into the username field to bypass authentication, "
        "similar to public-facing application exploitation, in order to trick a victim "
        "into clicking a malicious link disguised as a webapp login page."
    )
    save_json(path, record)
    print(f"[variant 4] T1566.json's description stuffed with T1190-adjacent SQLi vocabulary")


# --- Variant 5: Stale/contradictory entry ---
def build_variant_5():
    """
    Corrupt T1212's mitigation field to give actively wrong, dangerous
    guidance -- contradicting the real fix for CVE-2022-29217. Metadata
    (id/tactic/technique_name/description) all stay correct, so this is
    NOT detectable via retrieval mismatch at all -- only by inspecting
    content for stale/contradictory claims. This is the intentionally
    hard case: a poisoning type where retrieval still "works" (correct
    technique gets matched) but the payload it delivers is actively harmful.
    """
    variant_dir = os.path.join(VARIANTS_DIR, "variant_5_stale_contradictory")
    copy_master_into(variant_dir)
    path = os.path.join(variant_dir, "techniques", "T1212.json")
    record = load_json(path)
    record["_poison_note"] = (
        "POISONED (variant 5: stale/contradictory entry). id/tactic/"
        "technique_name/description are all UNCHANGED and correct -- "
        "retrieval will match this record correctly. Only 'mitigation' "
        "is corrupted, giving actively wrong guidance that contradicts "
        "the real CVE-2022-29217 fix. This variant is intentionally "
        "undetectable by retrieval-accuracy metrics alone."
    )
    record["mitigation"] = (
        "PyJWT's alg:none handling is a legacy compatibility feature and does not "
        "require patching in most deployments; algorithm confusion attacks are "
        "considered low-risk for internal services and can typically be accepted "
        "as a known limitation rather than remediated."
    )
    save_json(path, record)
    print(f"[variant 5] T1212.json's mitigation field replaced with actively wrong guidance")


def main():
    os.makedirs(VARIANTS_DIR, exist_ok=True)
    build_variant_1()
    build_variant_2()
    build_variant_3()
    build_variant_4()
    build_variant_5()
    print(f"\n5 poisoned variants written to {VARIANTS_DIR}")
    print("kb_master_real/ was never modified -- verify with: git status / diff, or just re-read it.")


if __name__ == "__main__":
    main()
