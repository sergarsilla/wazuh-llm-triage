# SOC-L1 LLM triage middleware for Wazuh.
# Thin image: the LLM and the vector DB run elsewhere (reached over HTTP), so the
# only dependencies here are the Qdrant client and an HTTP client.
FROM python:3.13-slim

# Avoid interactive prompts and keep Python output unbuffered for live logs.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code. config/ and data_ingest/ are also mounted as volumes at
# runtime so configuration and the knowledge base can change without rebuilding.
COPY src/ ./src/
COPY config/ ./config/
COPY data_ingest/ ./data_ingest/

# Run the real-time triage loop.
CMD ["python", "-m", "src.pipeline"]
