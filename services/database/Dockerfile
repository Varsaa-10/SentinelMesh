# SentinelMesh — Database Service
FROM postgres:15-alpine@sha256:23799e521dee9265a8b388ecf3bc0f1eaa34b95be67f5a76af4f8f6adb44c720

# Build-time tools for ENV2 scenarios (shred, useradd, scp)
RUN apk add --no-cache coreutils openssh-client shadow
