**Calibration with original-alert cluster bootstrap (140 original alerts)**

| track | predictor | Brier | Brier_CI95 | ECE10 | slope | intercept |
|---|---|---|---|---|---|---|
| A | manual_confidence_original | 0.235 | [0.231, 0.239] | 0.224 | 3.866 | 1.967 |
| A | raw_fused_score | 0.244 | [0.236, 0.252] | 0.230 | 4.956 | 3.402 |
| A | learned_LR | 0.091 | [0.083, 0.101] | 0.045 | 1.289 | 0.033 |
| B | manual_confidence_original | 0.390 | [0.383, 0.398] | 0.619 | 0.542 | -5.926 |
| B | raw_fused_score | 0.850 | [0.843, 0.856] | 0.919 | -0.287 | -4.935 |
| B | learned_LR | 0.004 | [0.0, 0.009] | 0.009 | 1.231 | -0.278 |
