# Held-out variant results (Step 6)

Run: eval/runs_heldout/20261015T051907Z (frozen). Detectors, KB and rewrite
rules frozen as tagged; nothing changed after seeing results. Result matches
the pre-registered prediction in eval/held_out_ground_truth.json exactly.

Detected (detector generalized across the method change):
- S1 UNION-based SQL injection
- S5 DB connection from a different ephemeral client
- S6 in-place log truncation
- S7 anonymous scrape of a different Grafana API path
- S9 SSH private key read

Detection gaps (variant evaded the frozen detector):
- S2 distributed password spray: never reaches the per-identifier failure threshold
- S3 second seeded account (testuser): detector only flags username=admin
- S4 HS384 forged token: accepted as valid; detector matches only algorithm=none
- S8 egress from the database container: rule watches only webapp and authservice

Summary: 5 of 9 variants still detected, 4 evaded. The gaps are threshold-,
identity-, algorithm- and container-scoped, not method-scoped.
