# Wazuh LLM Triage — SOC-L1 Intelligent Triage Middleware

Intercepts critical Wazuh alerts in real time, enriches them with corporate
context via **RAG (Qdrant + Ollama embeddings)**, classifies them with a **local
LLM (Ollama)**, and writes the verdict back into Wazuh so it drives a two-level
escalation. Optional **Active Response** is gated by an allowlist and a
kill-switch and is **dry-run by default**.

```
                          ┌──────────────────────────────┐
[alerts.json] ─► ingester ─► RAG (Qdrant) ─► LLM (Ollama) ─► verdict
                          └──────────────────────────────┘
                                     │                 │
                  re-inject verdict ◄┘                 └► Active Response
                  (Wazuh queue socket)                    (allowlist, dry-run)
```

The LLM and the vector DB are reached over HTTP, so they can run on the manager
itself or on any host with spare CPU/RAM reachable from it — no GPU required.

## How it triages

1. **Ingest** — non-blocking tail of `alerts.json`, filtered by `rule.level`
   (`min_alert_level`, default 7), rotation-safe.
2. **Retrieve** — the alert's salient fields (host, source IP, and, for
   anomaly-detector alerts, the user/process/command) are embedded and matched
   against a knowledge base of your assets and policies.
3. **Classify** — a local LLM returns a strict JSON verdict: `false_positive`,
   `real_risk_level` (LOW/MEDIUM/HIGH/CRITICAL), `technical_justification`,
   `requires_active_response`, `suggested_mitigation_command`.
4. **Escalate (two levels)** — the verdict is re-injected into Wazuh. A
   `MALICIOUS` verdict fires a high-level rule (dashboard + e-mail); a
   `FALSE_POSITIVE` verdict is recorded silently. The raw alert stays a low
   "review" signal — only the LLM verdict escalates it.

## Requirements

- Python 3.11+
- [Ollama](https://ollama.com) with two models pulled (CPU-friendly defaults):
  ```bash
  ollama pull qwen2.5:3b-instruct-q4_K_M   # triage LLM (alt: llama3.2:3b)
  ollama pull all-minilm                   # 384-dim embeddings
  ```
- [Qdrant](https://qdrant.tech) (multi-arch Docker image):
  ```bash
  docker run -d --name qdrant --restart unless-stopped \
    -p 6333:6333 -v "$HOME/qdrant_storage:/qdrant/storage" qdrant/qdrant
  ```

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Endpoints, models, paths and credentials are read from environment variables, so
no infrastructure-specific value lives in the repo. `config/app_config.json`
holds only `${VAR:-default}` placeholders with safe local defaults; override them
via a gitignored `.env` (copy `.env.example`):

```bash
cp .env.example .env
# edit .env, then load it:
set -a; source .env; set +a
```

| Variable | Purpose | Default |
|----------|---------|---------|
| `OLLAMA_URL` | Ollama endpoint | `http://localhost:11434` |
| `QDRANT_URL` | Qdrant endpoint | `http://localhost:6333` |
| `LLM_MODEL_NAME` | Triage model | `qwen2.5:3b-instruct-q4_K_M` |
| `EMBEDDING_MODEL_NAME` | Embedding model (384-dim) | `all-minilm` |
| `WAZUH_ALERTS_PATH` | Alert log to tail | `data_ingest/live_alerts.json` |
| `WAZUH_SOCKET_PATH` | Queue socket for verdict re-injection | `/var/ossec/queue/sockets/queue` |
| `WAZUH_API_URL` / `_USER` / `_PASSWORD` | Wazuh API (real Active Response only) | — |
| `KILL_SWITCH_FILE` | If this file exists, all Active Response is suppressed | `/var/ossec/.llm_triage_KILL` |

## Knowledge base

Generic, simulated example documents live in `data_ingest/knowledge_base/`. Add
your **real** asset inventory, network policies and operational baseline as
`.txt`/`.md` files under `data_ingest/knowledge_base/local/` — that folder is
gitignored, so your environment details are indexed but never committed. Then:

```bash
python data_ingest/populate_db.py     # (re)index the knowledge base into Qdrant
```

## Security model

- **Prompt injection** — the alert (including attacker-controlled fields like
  the command) is treated as untrusted data: it is wrapped in per-request
  random-nonce delimiters and the system prompt forbids obeying any instruction
  embedded in it.
- **Active Response is constrained** — only command names in
  `responder.command_allowlist` can ever be dispatched; the LLM's free-text
  suggestion is advisory and never executed. `responder.dry_run` (default
  `true`) logs the intended action without performing it.
- **Kill-switch** — `touch`-ing `KILL_SWITCH_FILE` instantly suppresses all
  Active Response, even in real mode.

## Running it (phased rollout)

### Phase 1 — Simulation (no manager needed)

Keep `WAZUH_ALERTS_PATH` at the default and replay the bundled sample alerts:

```bash
# Terminal 1 — start the triage loop
python -m src.pipeline

# Terminal 2 — feed sample alerts
python data_ingest/simulate_alerts.py --interval 3 --reset
```

Expect: the level-3 alert filtered out; the external brute force flagged
HIGH/CRITICAL; the internal scanner and the `ubuntu`/`docker` anomaly classified
as false positives (thanks to RAG); the download-and-exec and reverse-shell
anomalies flagged MALICIOUS; and the prompt-injection probe **not** changing the
verdict.

### Phase 2 — Live, dry-run, with verdict re-injection

On the Wazuh manager:

1. Install the verdict rules and reload the manager:
   ```bash
   sudo cp rules/llm_triage_rules.xml /var/ossec/etc/rules/
   sudo systemctl restart wazuh-manager
   ```
2. Point the middleware at the live log and enable re-injection (keep
   `responder.dry_run: true`):
   ```bash
   export WAZUH_ALERTS_PATH=/var/ossec/logs/alerts/alerts.json
   # set "verdict_injection": { "enabled": true } in config/app_config.json
   ```
   Run as a user that can **read** `alerts.json` and **write** the queue socket
   (the `wazuh` group, or root). Verdicts appear in the dashboard under
   `rule.groups: llm_triage`; a `MALICIOUS` verdict triggers your existing Wazuh
   e-mail.

### Phase 3 — Real Active Response (only once you trust the verdicts)

Configure `responder.command_allowlist`, make sure the matching `<command>` /
`<active-response>` blocks exist in the manager's `ossec.conf`, set the
`WAZUH_API_*` variables, and flip `responder.dry_run` to `false`. Keep
`KILL_SWITCH_FILE` handy as an instant off-switch.

## Integration with the anomaly detector

This middleware consumes the level-12 alerts (`rule.id 100100`) injected by a
separate **wazuh-anomaly-detector** project, which carry enrichment under
`data.anomaly_detector.*` (agent, user, process, command, score). The two
projects are decoupled and integrate only through that
`alerts.json` contract. The detector flags *statistical rarity*, not malice; this
layer's job is to use RAG context to dismiss routine admin activity and escalate
only genuine threats.

## Project layout

| Path | Responsibility |
|------|----------------|
| `src/config.py` | Config loader with `${VAR:-default}` env expansion |
| `src/ingester.py` | Non-blocking `tail -f` of `alerts.json`, severity filter, self-verdict skip |
| `src/rag_manager.py` | Ollama embeddings + Qdrant cosine-similarity retrieval |
| `src/llm_client.py` | Ollama chat client, schema-enforced JSON verdict, injection-hardened prompt |
| `src/responder.py` | Active Response with allowlist, kill-switch and dry-run |
| `src/wazuh_injector.py` | Re-injects verdicts into Wazuh via the queue socket |
| `src/verdict_contract.py` | Shared verdict location/rule ids |
| `src/pipeline.py` | Threaded producer/consumer orchestrator |
| `rules/llm_triage_rules.xml` | Manager-side rules that score re-injected verdicts |
| `data_ingest/populate_db.py` | Index the knowledge base into Qdrant |
| `data_ingest/simulate_alerts.py` | Replay sample alerts (no manager needed) |
