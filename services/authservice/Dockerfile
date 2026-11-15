# SentinelMesh — Authentication Service
FROM python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535

WORKDIR /app

# Install curl for healthchecks and debugging tools for ENV2 scenarios
RUN apt-get update && apt-get install -y --no-install-recommends curl gdb strace \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 120 --retries 10 -r requirements.txt

COPY app.py .

EXPOSE 5001

CMD ["python", "app.py"]
