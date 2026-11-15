# Security review (M7)
Scope: SentinelMesh-X additions and the interaction with the original lab. Not a penetration test; no external review was done.
## Controls implemented, each with tests
| Control | Tests | Residual risk |
|---|---|---|
| Fail-closed policy engine; confidence can only escalate (`safety.py`) | `test_m2_safety.py` (20) | Impact tiers come from team-assigned severity/criticality; all lab scenarios are analyst/admin so autonomy was never exercised |
| Policy-token-checked executor simulator with allowlists, approval, kill switch | forged/edited decision, allowlist, approval, kill-switch tests | Simulator only; no real action path was built or tested; process-local HMAC token is not a distributed trust mechanism |
| Field trust tiers, sanitiser, trusted-view conflict check | classification, nested removal, unicode/oversize tests; `m2_safety_eval.json`; `m6_adaptive_attacks.json` | Tier assignment is by field name and was justified by sensor semantics, then chosen between two options on dev data; partial-trust fields (file paths, client_ip) can be forged (mimicry attack measured) |
| Signed KB manifest, rollback protection | `test_m3_integrity.py` (9); 12 attack classes x 300 trials = 100% detection, 0/500 false positives | Local-dev keys; no rotation/revocation/HSM; semantic poisoning before signing is out of scope |
| Hash-chained redacting audit log, decision records | chain edit/delete/reorder/truncate tests; secrets-not-logged test | Truncation detectable only with an externally stored head hash; no log shipping |
| Warnings-as-errors suite | full suite passes in a clean venv | Starlette notice resolved by installing `httpx2` (dependency, not project code) |
## Findings in the original system
1. **Inverted confidence handling:** legacy risk = confidence x severity x criticality, so a low-confidence prediction scores low risk and routes to `auto`. This produced 92.8% under-escalation and 43.8% auto-on-wrong-prediction in the degraded/attack evaluation (`m2_safety_eval.json`). Replaced in the X pipeline; the original `response/risk_scoring.py` is unchanged.
2. Boolean-returning tests could not fail (fixed earlier); Pydantic `Field(example=)` and `.dict()` deprecations in `backend/app.py` fixed (behaviour unchanged, backend tests pass).
3. The ngrok service is opt-in (`--profile tunnel`). Host ports remain bound to 127.0.0.1. Weak credentials and PostgreSQL `trust` on 0.0.0.0/0 are intentional lab settings and were NOT changed; a separate safe-demonstration profile was NOT built (listed in PENDING.md).
## Not done
Gitleaks/secret scan, container image pinning by digest, safe-demo compose profile, penetration test, threat model review by a second person.
