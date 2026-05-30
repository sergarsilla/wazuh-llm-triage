# Wazuh LLM Triage — SOC-L1 Intelligent Triage Middleware

Intercepts critical Wazuh alerts in real time, enriches them with corporate
context via **RAG (Qdrant + Ollama embeddings)**, classifies them with a **local
LLM (Ollama / Llama-3)**, and — when warranted — triggers **Wazuh Active
Response** (dry-run by default).

```
[alerts.json] -> ingester.py -> queue -> rag_manager.py <-> Qdrant
                                            |
                                            v  (alert + context)
[Active Response] <- responder.py <- llm_client.py (Ollama)
```

## Requirements

- Python 3.11+ (validated on 3.14)
- [Ollama](https://ollama.com) running locally with two models:
  ```bash
  ollama pull llama3:8b-instruct-q4_K_M   # triage LLM
  ollama pull all-minilm                  # 384-dim embeddings
  ```
- Qdrant (Docker):
  ```bash
  docker run -d -p 6333:6333 -v "$HOME/qdrant_storage:/qdrant/storage" \
    --name qdrant qdrant/qdrant
  ```

## Setup

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

All endpoints, models, the severity threshold (`min_alert_level`, default 7)
and the responder mode live in `config/app_config.json`.

## 1. Index the knowledge base (RAG)

```bash
python data_ingest/populate_db.py
```

## 2. Run the pipeline (simulation mode — works on this PC)

Your workstation is a Wazuh *agent*, not a manager, so there is no local
`alerts.json`. Use the bundled feeder to replay realistic alerts:

```bash
# Terminal 1 — start the autonomous triage loop
python -m src.pipeline

# Terminal 2 — feed sample alerts into the watched file
python data_ingest/simulate_alerts.py --interval 3 --reset
```

You should see: the level-3 alert filtered out; an external SSH brute force
flagged HIGH/CRITICAL with a suggested `firewall-drop`; the internal scanner
alert classified as a **false positive** (thanks to RAG); and a root login on
the crown-jewel DB flagged CRITICAL.

## 3. Run against your real Oracle Wazuh manager

On the Oracle Cloud (free-tier) box that runs the **Wazuh Manager**, deploy this
project and point it at the live alert log:

1. Install Ollama + Qdrant on the manager (or reach them over the network) and
   pull the two models.
2. Give the service read access to the alert log and edit
   `config/app_config.json`:
   ```json
   "wazuh_alerts_path": "/var/ossec/logs/alerts/alerts.json"
   ```
   The `wazuh` user owns that file; run the pipeline as a user in the `wazuh`
   group (or as root) so it can read it.
3. To enable **real** Active Response, set in `config/app_config.json`:
   ```json
   "responder": {
     "dry_run": false,
     "wazuh_api_url": "https://127.0.0.1:55000",
     "wazuh_api_user": "wazuh-wui",
     "wazuh_api_password": "<your-api-password>",
     "verify_ssl": false
   }
   ```
   and make sure a matching command (e.g. `firewall-drop`) is configured in the
   manager's `ossec.conf` `<active-response>` / `<command>` blocks. Until then,
   keep `dry_run: true` to log intended actions without executing them.

> This PC (a Wazuh agent) can also forward its own alerts to the Oracle manager;
> the middleware always reads the **manager's** aggregated `alerts.json`.

## Project layout

| Path | Responsibility |
|------|----------------|
| `src/ingester.py` | Non-blocking `tail -f` of `alerts.json`, severity filter, rotation-safe |
| `src/rag_manager.py` | Ollama embeddings + Qdrant cosine-similarity retrieval |
| `src/llm_client.py` | Ollama chat client, schema-enforced JSON triage verdict |
| `src/responder.py` | Wazuh Active Response (dry-run by default) |
| `src/pipeline.py` | Threaded producer/consumer orchestrator |
| `data_ingest/populate_db.py` | Index the knowledge base into Qdrant |
| `data_ingest/simulate_alerts.py` | Replay sample alerts (no manager needed) |
