#!/bin/bash
# Held-out variant of S9 (Sensitive Credential File Read, T1003.008).
# Original: cat /etc/shadow in sentinelmesh-webapp.
# Variant : read an SSH private key (/root/.ssh/id_rsa) - a DIFFERENT
# credential file the rule also lists (/root/.ssh/*). A decoy key is planted
# first so there is a real file to read; cat does a plain absolute-path open
# so the read reliably reaches the rule. Same post-foothold weakness,
# different target file.
# Expected: detection FIRES.
echo "========================================="
echo "S9 held-out variant - SSH private key read"
echo "========================================="
docker exec sentinelmesh-webapp sh -c '
  mkdir -p /root/.ssh
  printf "%s\n" "-----BEGIN OPENSSH PRIVATE KEY-----" "decoy-not-a-real-key" "-----END OPENSSH PRIVATE KEY-----" > /root/.ssh/id_rsa
  chmod 600 /root/.ssh/id_rsa
  cat /root/.ssh/id_rsa > /dev/null
'
echo
echo "[done] SSH private key read via cat."
