"""M6: audited, fail-closed processing path: sanitise -> retrieve (full + trusted view) -> calibrate -> policy -> (simulated) execution -> decision record -> tamper-evident log."""
from __future__ import annotations
import time
import traceback
from typing import Any, Callable, Dict, List, Optional, Sequence

from .audit import AuditLog, decision_record
from .retrieval import DAHRConfig, KBIndex, dahr_components, dahr_combine
from .safety import (DecisionInput, PolicyEngine, SafeExecutor, classify_field, flatten, provenance, sanitise_text, trusted_view, UNTRUSTED, TRUSTED, PARTIAL)
from .calibration import features


class SafePipeline:
    def __init__(self, index: Optional[KBIndex], cfg: DAHRConfig, calibrator, policy: PolicyEngine, audit: AuditLog, kb_version: str, integrity_ok: bool,
                 supported: Sequence[str], sev_by_technique: Dict[str, int], crit_by_service: Dict[str, int], query_builder: Callable[[Dict], str],
                 executor: Optional[SafeExecutor] = None, retriever_version: str = "DAHR-1.0"):
        self.ix, self.cfg, self.cal, self.policy, self.audit = index, cfg, calibrator, policy, audit
        self.kb_version, self.integrity_ok, self.supported = kb_version, integrity_ok, list(supported)
        self.sev, self.crit, self.qb, self.exec, self.rv = sev_by_technique, crit_by_service, query_builder, executor or SafeExecutor(), retriever_version

    def _san(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        import copy
        a = copy.deepcopy(alert)
        def walk(d, pre=""):
            for k, v in d.items():
                p = f"{pre}.{k}" if pre else k
                if isinstance(v, dict): walk(v, p)
                elif isinstance(v, str) and classify_field(p) == UNTRUSTED: d[k] = sanitise_text(v)
        walk(a.get("event") or {})
        return a

    def _comp(self, alert: Dict[str, Any]):
        try:
            q = self.qb(alert)
        except ValueError:
            q = ""
        return dahr_components(self.ix, q, alert)

    def process(self, alert: Dict[str, Any], alert_id: str, requested_action: str = "log_only", target: str = "webapp", human_approval: Optional[Dict] = None) -> Dict[str, Any]:
        t0 = time.perf_counter()
        pred = conf = None; evidence: List[Dict] = []; rejected: List[Dict] = []; inp = None; ok = True
        prov = provenance(alert)
        try:
            a = self._san(alert); cF = self._comp(a); rkF = dahr_combine(cF, self.cfg)
            tv = trusted_view(a); cT = self._comp(tv); rkT = dahr_combine(cT, self.cfg)
            pred = rkF.ids[0]; tpred = rkT.ids[0]
            rec = self.ix.recs[self.ix.pos[pred]]; src = (a.get("source") or "").replace("-", "_")
            conf = float(self.cal.predict([features(rkF.parts, rkF.scores, 0.5 if not rec.sources else float(src in rec.sources))])[0])
            service = str(a.get("service") or (a.get("event") or {}).get("container.name", "")).replace("sentinelmesh-", "")
            inp = DecisionInput(pred, conf, self.supported, float(cF.cov), bool(tpred == pred and cT.fld.max() > 0), tpred != pred, self.integrity_ok, True, False,
                                self.sev.get(pred, 5), self.crit.get(service, 5), requested_action, tuple(self.sev.get(i, 5) for i in rkF.ids[:3]))
            evidence = [{"field": p["field"], "tier": p["tier"]} for p in prov] + [{"channel": k, "value": round(float(v), 4)} for k, v in rkF.parts.items() if k in ("field_top", "sem_top", "field_cov")]
            rejected = [{"technique": i, "score": round(s, 4)} for i, s in zip(rkF.ids[1:6], rkF.scores[1:6])]
        except Exception as e:                                         # fail closed: never raise into the response path
            ok = False
            self.audit.append({"event": "retrieval_failure", "alert_id": alert_id, "error": type(e).__name__})
        dec = self.policy.decide(inp if inp is not None else DecisionInput(None, None, self.supported, retrieval_ok=False, integrity_ok=self.integrity_ok, requested_action=requested_action))
        ex = self.exec.execute(dec, requested_action, target, human_approval)
        rec_ = decision_record(alert_id, self.kb_version, self.rv, pred, conf, evidence, rejected, "verified" if self.integrity_ok else "FAILED", dec.route, list(dec.reasons),
                               f"{'executed' if ex.executed else 'not_executed'}:{ex.reason}", human_approval)
        rec_["abstained"] = dec.abstain; rec_["latency_ms"] = round((time.perf_counter() - t0) * 1000, 3)
        self.audit.append(rec_)
        return rec_
