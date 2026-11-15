**Cryptographic KB integrity (300 trials per attack; local-dev Ed25519 signing)**

| attack | detection_rate | expected_failure_code_rate |
|---|---|---|
| description_modification | 1.000 | 1.000 |
| rule_modification | 1.000 | 1.000 |
| record_replacement_same_id | 1.000 | 1.000 |
| record_replacement_content_swap | 1.000 | 1.000 |
| record_deletion | 1.000 | 1.000 |
| record_insertion | 1.000 | 1.000 |
| manifest_modification | 1.000 | 1.000 |
| signature_modification | 1.000 | 1.000 |
| rollback_to_old_signed_kb | 1.000 | 1.000 |
| invalid_signing_key | 1.000 | 1.000 |
| fork_same_version | 1.000 | 1.000 |
| chain_break_skipped_version | 1.000 | 1.000 |
| false_positive_benign_reserialisation | 0.000 |  |
