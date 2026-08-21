# KB Master — CTI-to-ATT&CK Benchmark Notes

**Status:** Dataset identified and format confirmed (Day 4 of KB week)  
**Actual comparison:** Deferred — planned for a later task as specified in the PRD.

---

## Identified Dataset: TRAM (Threat Report ATT&CK Mapper)

**Repository:** https://github.com/mitre-attack/tram  
**Maintainer:** MITRE ATT&CK  
**License:** Apache 2.0

### What it is

TRAM is a tool and labeled dataset developed by MITRE that maps sentences from Cyber Threat Intelligence (CTI) reports to ATT&CK techniques. The dataset consists of annotated sentences extracted from public threat reports (APT campaigns, malware analysis writeups, etc.), where each sentence is labeled with zero or more ATT&CK technique IDs.

### Format

The TRAM dataset is distributed as JSON files:

```json
{
  "doc-id": "report-001",
  "text": "The attacker used a spearphishing email with a malicious attachment to gain initial access.",
  "sentences": [
    {
      "text": "The attacker used a spearphishing email...",
      "labels": [
        {
          "technique_id": "T1566.001",
          "technique_name": "Phishing: Spearphishing Attachment",
          "start_index": 0,
          "end_index": 85
        }
      ]
    }
  ]
}
```

Key fields:
- `doc-id` — unique report identifier
- `sentences[].text` — individual sentence from the CTI report
- `sentences[].labels[].technique_id` — ATT&CK technique ID (matches our `id` field in technique records)
- `sentences[].labels[].technique_name` — ATT&CK technique name (matches our `technique_name` field)

### Why this dataset fits our use case

| Property | Value |
|---|---|
| ATT&CK version coverage | ATT&CK v8–v12 (technique IDs stable for T1190, T1110, T1078, T1212, T1021, T1070, T1041, T1003) |
| Sentence-level labels | Yes — enables precision/recall at technique level |
| Open access | Yes — Apache 2.0 license, no registration needed |
| Technique ID format | Standard `T####` / `T####.###` — directly matchable to our KB `id` field |
| Lab technique overlap | T1190, T1110, T1078 are well-represented in the corpus |

### Secondary Option: MITRE CTID Attack Flow Dataset

**Repository:** https://github.com/center-for-threat-informed-defense/attack-flow  
**Maintainer:** Center for Threat-Informed Defense (CTID)

A complementary dataset representing multi-step attack flows (chains of techniques) as structured JSON graphs. The `attack-flow` format models technique sequencing — directly relevant for evaluating S10 (multi-stage chain) retrieval quality.

Format: ATT&CK Flow v2.0 JSON with `attack-flow`, `attack-action` (technique reference), and `attack-condition` nodes.

---

## How the Comparison Will Work (Future Task)

The actual comparison is **out of scope for this week** per the PRD. When the comparison task begins:

1. **Load TRAM sentences** where at least one label matches a technique in our KB (T1190, T1110, T1078, T1212, T1021, T1070, T1041, T1003.008)
2. **Use Person 2's RAG engine** to retrieve the top-k techniques for each TRAM sentence
3. **Score retrieval accuracy**: for each query sentence, check whether the ground-truth technique ID appears in the top-k results
4. **Distractor filtering test**: check how often distractor techniques (T1566, T1082, etc.) are mistakenly returned instead of the correct technique

This approach produces a Precision@k and Recall@k score against a public, independently-labeled benchmark — an objective external validity check on the RAG layer quality.

---

## Confirmed Format Compatibility

| TRAM field | KB Master field | Match? |
|---|---|---|
| `technique_id` | `id` | ✅ exact format |
| `technique_name` | `technique_name` | ✅ exact format |
| `sentences[].text` | `description` (extended) | ✅ comparable |
| *(no CVE field)* | `related_cves` | ➖ TRAM doesn't label CVEs |

No format conversion needed between TRAM technique IDs and KB technique IDs — they use the same ATT&CK identifier convention.
