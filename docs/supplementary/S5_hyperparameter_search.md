# S5. Hyper-parameter search
Grid (Track A): w_f {0.1,0.25,0.4,0.55} x w_s {0.1,0.2,0.3,0.45} x w_b {0,0.1,0.2} x w_h {0,0.1,0.2,0.3} x top_m {2,3,5} x adaptive {T,F} = 1,152 configs; Track B drops w_f (288 configs). Objective: MRR on development captures under perturbation (drop 0.3/0.5, noise 0.15, rename 0.5/1.0 + clean).

Pre-M1 (frozen, `results_x/dahr_tuned.json`) best: `{'w_f': 0.55, 'w_s': 0.1, 'w_b': 0.2, 'w_h': 0.0, 'top_m': 5, 'adaptive': False, 'use_field': True, 'use_sem': True, 'use_bm25': True, 'use_hier': True}`; dev MRR 0.9257 vs default 0.8961.

Nested LOCO (M1): Track A mean MRR nested 0.9244, old procedure 0.9244, default 0.8966; Track B nested 0.0654, old 0.0661, default 0.0640.

Full per-fold values and chosen configs: `results_x_v2/tuning_nested.json`.
