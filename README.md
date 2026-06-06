# 🛡️ Wazuh LLM Triage

SOC Level-1 triage middleware for [Wazuh](https://wazuh.com/). It intercepts
critical alerts in real time, enriches them with your own context via **RAG
(Qdrant + Ollama embeddings)**, classifies them with a **local LLM (Ollama)**,
and writes the verdict back into Wazuh to drive a **two-level escalation** —
without sending anything to a third party.

<p>
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-blue">
  <img alt="LLM" src="https://img.shields.io/badge/LLM-Ollama%20(CPU)-000000">
  <img alt="VectorDB" src="https://img.shields.io/badge/vector%20db-Qdrant-dc244c">
  <img alt="Docker" src="https://img.shields.io/badge/docker-ready-2496ed">
</p>

```
                          ┌──────────────────────────────┐
[alerts.json] ─► ingester ─► RAG (Qdrant) ─► LLM (Ollama) ─► verdict
                          └──────────────────────────────┘
                                     │                 │
                  re-inject verdict ◄┘                 └► Active Response
                  (Wazuh queue socket)                    (allowlist, dry-run)
```

The LLM and the vector DB are reached over HTTP, so they can run on the manager
itself or on any host with spare CPU/RAM reachable from it — **no GPU required**.

## Table of Contents

- [How it works](#-how-it-works)
- [Tech stack](#-tech-stack)
- [Project structure](#-project-structure)
- [Quick start (Docker)](#-quick-start-docker)
- [Local development (simulation)](#-local-development-simulation)
- [Configuration](#-configuration)
- [Knowledge base](#-knowledge-base)
- [Security model](#-security-model)
- [Phased rollout](#-phased-rollout)
- [Integration with the anomaly detector](#-integration-with-the-anomaly-detector)

## 🧠 How it works

| Step | What happens |
|------|--------------|
| **Ingest** | Non-blocking tail of `alerts.json`, filtered by `rule.level` (default ≥ 7), rotation-safe. It skips its own re-injected verdicts so it never loops. |
| **Retrieve** | The alert's salient fields (host, source IP and, for anomaly-detector alerts, the user/process/command) are embedded and matched against your knowledge base. |
| **Classify** | A local LLM returns a strict JSON verdict: `false_positive`, `real_risk_level` (LOW/MEDIUM/HIGH/CRITICAL), `technical_justification`, `requires_active_response`, `suggested_mitigation_command`. |
| **Escalate** | The verdict is re-injected into Wazuh. A `MALICIOUS` verdict fires a high-level rule (dashboard + e-mail); a `FALSE_POSITIVE` is recorded silently. The raw alert stays a low "review" signal — only the LLM verdict escalates it. |

## 🧰 Tech stack

- **Python 3.11+** (the Docker image uses `python:3.13-slim`).
- **Ollama** — local LLM (`qwen2.5:3b-instruct-q4_K_M` by default; alt `llama3.2:3b`) and embeddings (`all-minilm`, 384-dim). CPU-only.
- **Qdrant** — vector DB for cosine-similarity retrieval.
- Runtime deps are just `qdrant-client` + `requests`; everything else is the standard library.

## 📁 Project structure

| Path | Responsibility |
|------|----------------|
| `src/config.py` | Config loader with `${VAR:-default}` env expansion |
| `src/ingester.py` | Non-blocking `tail -f` of `alerts.json`, severity filter, self-verdict skip |
| `src/rag_manager.py` | Ollama embeddings + Qdrant retrieval |
| `src/llm_client.py` | Ollama chat client, schema-enforced verdict, injection-hardened prompt |
| `src/responder.py` | Active Response with allowlist, kill-switch and dry-run |
| `src/wazuh_injector.py` | Re-injects verdicts into Wazuh via the queue socket |
| `src/verdict_contract.py` | Shared verdict location / rule ids |
| `src/pipeline.py` | Threaded producer/consumer orchestrator |
| `rules/llm_triage_rules.xml` | Manager-side rules that score re-injected verdicts |
| `data_ingest/populate_db.py` | Index the knowledge base into Qdrant |
| `data_ingest/simulate_alerts.py` | Replay sample alerts (no manager needed) |

## 🚀 Quick start (Docker)

Run this **on the Wazuh manager host** (it needs `alerts.json` and the queue
socket). Ollama + Qdrant must already be running and reachable (see
[Configuration](#-configuration)).

```bash
# 1. Configure: copy the template and fill in your endpoints/paths.
cp .env.example .env && nano .env

# 2. Add your environment notes to the (gitignored) local knowledge base.
nano data_ingest/knowledge_base/local/environment.txt

# 3. Install the verdict rules on the manager and reload it.
sudo cp rules/llm_triage_rules.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager

# 4. Index the knowledge base into Qdrant (one-off; re-run when the KB changes).
docker compose run --rm populate

# 5. Start the triage middleware (runs forever, restarts on reboot).
docker compose up -d triage
docker compose logs -f triage
```

`deploy.sh.example` shows how to push the repo to the manager and rebuild
remotely; copy it to `deploy.sh` (gitignored) and set your host.

## 🧪 Local development (simulation)

No manager needed — replay the bundled sample alerts against your Ollama/Qdrant:

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python data_ingest/populate_db.py          # index the knowledge base

# Terminal 1 — start the triage loop
python -m src.pipeline
# Terminal 2 — feed sample alerts
python data_ingest/simulate_alerts.py --interval 3 --reset
```

Expect: the level-3 alert filtered out; the external brute force flagged
HIGH/CRITICAL; the internal scanner and the `ubuntu`/`docker` anomaly classified
as false positives; the download-and-exec and reverse-shell anomalies flagged
MALICIOUS; and the prompt-injection probe **not** changing the verdict.

## ⚙️ Configuration

Endpoints, models, paths and credentials come from environment variables, so no
infrastructure-specific value lives in the repo. `config/app_config.json` holds
only `${VAR:-default}` placeholders; override them via a gitignored `.env`
(`docker compose` reads it automatically; for local runs use
`set -a; source .env; set +a`).

| Variable | Purpose | Default |
|----------|---------|---------|
| `OLLAMA_URL` | Ollama endpoint (use the private IP of the inference host) | `http://localhost:11434` |
| `QDRANT_URL` | Qdrant endpoint | `http://localhost:6333` |
| `LLM_MODEL_NAME` | Triage model | `qwen2.5:3b-instruct-q4_K_M` |
| `EMBEDDING_MODEL_NAME` | Embedding model (384-dim) | `all-minilm` |
| `WAZUH_ALERTS_PATH` | Alert log to tail (set to `/var/ossec/logs/alerts/alerts.json` on the manager) | `data_ingest/live_alerts.json` |
| `WAZUH_SOCKET_PATH` | Queue socket for verdict re-injection | `/var/ossec/queue/sockets/queue` |
| `WAZUH_API_URL` / `_USER` / `_PASSWORD` | Wazuh API (real Active Response only) | — |
| `KILL_SWITCH_FILE` | If this file exists, all Active Response is suppressed | `/var/ossec/.llm_triage_KILL` |

Behavioural toggles live in `config/app_config.json` (mounted into the
container): `min_alert_level`, `rag_top_k`, `verdict_injection.enabled`, and the
`responder` block (`dry_run`, `command_allowlist`, `default_command`).

## 📚 Knowledge base

The knowledge base is just plain-text notes about **your** environment that the
LLM reads to decide whether an alert is normal *for you*. Generic, simulated
examples live in `data_ingest/knowledge_base/`. Put your **real** asset
inventory, admin accounts and policies in
`data_ingest/knowledge_base/local/` — that folder is **gitignored**, so your
environment details are indexed but never committed. A starter
`local/environment.txt` is provided to fill in. Re-run `populate` after any
change.

## 🔒 Security model

- **Prompt injection** — the alert (including attacker-controlled fields such as
  the command) is treated as untrusted data: it is wrapped in per-request
  random-nonce delimiters and the system prompt forbids obeying any instruction
  embedded in it.
- **Constrained Active Response** — only command names in
  `responder.command_allowlist` can ever be dispatched; the LLM's free-text
  suggestion is advisory and never executed. `responder.dry_run` (default
  `true`) logs the intended action without performing it.
- **Kill-switch** — `touch`-ing `KILL_SWITCH_FILE` instantly suppresses all
  Active Response, even in real mode.

## 🪜 Phased rollout

1. **Simulation** — validate verdicts and measure latency with the bundled
   sample alerts (see [Local development](#-local-development-simulation)).
2. **Live dry-run** — point `WAZUH_ALERTS_PATH` at the real log, set
   `verdict_injection.enabled: true`, keep `responder.dry_run: true`. Verdicts
   appear in the dashboard under `rule.groups: llm_triage`; a `MALICIOUS` verdict
   triggers your existing Wazuh e-mail.
3. **Real Active Response** — only once you trust the verdicts: configure
   `command_allowlist`, the matching `<command>`/`<active-response>` blocks in
   `ossec.conf` and the `WAZUH_API_*` variables, then set
   `responder.dry_run: false`.

## 🔗 Integration with the anomaly detector

This middleware consumes the level-12 alerts (`rule.id 100100`) injected by a
separate **wazuh-anomaly-detector** project, which carry enrichment under
`data.anomaly_detector.*` (agent, user, process, command, score). The two
projects are decoupled and integrate only through that `alerts.json` contract.
The detector flags *statistical rarity*, not malice; this layer's job is to use
RAG context to dismiss routine admin activity and escalate only genuine threats.
