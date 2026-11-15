**Routing under degraded and attacked inputs (6,160 observations of 140 alerts; oracle never selects auto)**

| policy | under_escalation | over_escalation | auto_rate | auto_on_wrong_prediction | route_matches_oracle |
|---|---|---|---|---|---|
| P0_legacy_manual | 0.928 | 0.000 | 0.651 | 0.438 | 0.072 |
| P1_learned_conf_legacy_formula | 0.649 | 0.000 | 0.561 | 0.439 | 0.351 |
| P2_safety_gate | 0.045 | 0.030 | 0.000 | 0.000 | 0.924 |
