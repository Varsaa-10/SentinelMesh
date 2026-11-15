"""M1 helpers: Track A / Track B inputs."""
from bench import *
from bench import _parse_technique  # noqa
from sentinelmesh_x.track_b import (build_independent_query, independent_alert, forbidden_phrases, assert_query_clean, assert_alert_clean,
                                    assert_kb_clean, leakage_scan, LeakageError, input_schema_hash)
from eval.alert_query import falco_output_templates

OUT2 = ROOT / "results_x_v2"
OUT2.mkdir(exist_ok=True)


def save2(name, obj):
    p = OUT2 / name
    p.write_text(json.dumps(obj, indent=1, default=str))
    return p


def all_titles():
    S = alert_sets()
    t = {r["alert"].get("title", "") for k in S for r in S[k]} | set(falco_output_templates().keys()) | {d.rule_name for d in detectors()}
    return sorted(x for x in t if x)


def phrases():
    return forbidden_phrases(all_titles(), falco_output_templates().values())


def attach_trackb(rows):
    ph = phrases()
    for r in rows:
        r["alertB"] = independent_alert(r["alert"])
        r["qB"] = build_independent_query(r["alert"])
        assert_alert_clean(r["alertB"]); assert_query_clean(r["qB"], ph)
    return rows


def trackb_row(row, alert):
    """Row view for Track B used by the shared runners: query = independent query of (possibly perturbed) alert."""
    a = independent_alert(alert)
    q = build_independent_query(alert) if a["event"] else ""
    return {**row, "alert": a, "queries": {"indep": q}}


def make_index_B(corpus, **kw):
    raw = build_raw_condition(corpus, "mitre")
    assert_kb_clean(raw, [clean_record(r) for r in load_corpus(corpus)])
    return make_index(corpus, "mitre", with_field=False, **kw)
