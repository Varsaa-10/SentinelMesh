# SentinelMesh — Authentication Service
FROM python:3.11-slim

WORKDIR /app

# Install curl for healthchecks and debugging tools for ENV2 scenarios
RUN apt-get update && apt-get install -y --no-install-recommends curl gdb strace \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 120 --retries 10 -r requirements.txt

COPY app.py .

EXPOSE 5001

CMD ["python", "app.py"]
