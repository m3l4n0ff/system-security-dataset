# System Security -- OpenProject

Labeled cybersecurity dataset built on a live OpenProject instance. Normal and attack traffic captured, normalized to MITRE CAR format, and enriched with distributed traces for intrusion detection research.

## Architecture

```
Gatling (simulations) ──► Caddy proxy ──► Rails (OpenProject) ──► PostgreSQL
                              │                   │
                         OpenTelemetry         Logs (JSON)
                              │                   │
                              ▼                   ▼
                           Jaeger            Filebeat ──► Logstash ──► Elasticsearch
                        (traces)           (CAR normalization)            │
                                                                      Kibana
```

## Attack Scenarios

| # | Simulation | MITRE Technique | Tactic |
|---|---|---|---|
| 1 | Normal browsing | -- | Baseline |
| 2 | Credential Stuffing | T1078 | Credential Access |
| 3 | API Reconnaissance | T1083 | Discovery |
| 4 | C2 Beaconing | T1071.001 | Command & Control |
| 5 | Application DoS | T1498.002 | Impact |
| 6 | SQL Injection / XSS | T1190 | Initial Access |
| 7 | Vulnerability Scanning | T1595.002 | Reconnaissance |
| 8 | Privilege Escalation / IDOR | T1548 | Privilege Escalation |

## Dataset Output

| File | Description |
|---|---|
| `dataset/openproject-final-dataset.json` | Final consolidated dataset with all 8 scenarios |
| `dataset/openproject-car-dataset.csv` | Labeled events in MITRE CAR format (semicolon-delimited, UTF-8 BOM) |
| `dataset/openproject-jaeger-traces.csv` | OpenTelemetry spans from the Caddy proxy |
| `dataset/openproject-traces.csv` | Events grouped by Rails trace ID |

### CAR fields per event

`@timestamp`, `trace.id`, `event.label`, `scenario.id`, `attack.technique`, `attack.tactic`, `car.action`, `car.object`, `car.url_remainder`, `car.response_status_code`, `car.response_body_size`, `car.source_ip`, `car.user_agent`, `car.http_method`, `car.protocol`, `car.destination_port`, `car.request_body_size`, `car.duration_ms`, `container.name`, `container.image.name`

## Project Structure

```
deploy/openproject/
├── docker-compose.yml                  # OpenProject stack
├── docker-compose.logging.yml          # ELK + Jaeger
├── docker-compose.labels-*.yml         # Per-experiment label overlays (x8)
├── proxy/
│   ├── Caddyfile.template              # Reverse proxy + OpenTelemetry tracing
│   └── Dockerfile
├── filebeat/filebeat.yml               # Log collection config
└── logstash/pipeline/
    └── car-normalization.conf          # Grok parsing + CAR field extraction

tests/
├── run-experiments.sh                  # Runs all 8 experiments sequentially
└── gatling/
    ├── docker-compose.experiments.yml  # Containerized Gatling services
    └── simulations/openproject/        # Scala simulation files (x8)

dataset/                                # Exported CSV files
```

## How to Run

### Prerequisites

- Docker and Docker Compose
- Gatling 3.10.3 (extracted in `tests/gatling-3.10.3/`)
- ~8 GB RAM available

### Start the stacks

```bash
cd deploy/openproject

# Start OpenProject
docker compose up -d

# Start observability (ELK + Jaeger)
docker compose -f docker-compose.logging.yml up -d
```

### Run all experiments

```bash
cd tests
bash run-experiments.sh
```

This runs each simulation with its label overlay, waits for log ingestion, and reports event counts.

### Import the Kibana dashboard

```bash
curl -X POST "http://localhost:5602/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  --form file=@kibana-dashboard.ndjson
```

This loads the **[Security] OpenProject - Attack Detection** dashboard with 5 panels: normal vs malicious distribution, MITRE tactics/techniques breakdown, HTTP response codes, and top targeted URIs. Open it from Kibana > Dashboard.

> The dashboard expects the `openproject-car-*` index pattern. Make sure experiments have been run and data is indexed before importing.

### Export the dataset

Query Elasticsearch on `localhost:9201` for the `openproject-car-*` index. Jaeger UI is available at `localhost:16686`.

## Labeling Mechanism

Each experiment applies a Docker Compose label overlay (`docker-compose.labels-*.yml`) to the `web` and `proxy` containers. Filebeat reads Docker container labels and injects them into every log event as metadata fields (`event.label`, `scenario.id`, `attack.technique`, `attack.tactic`). Logstash then parses the Caddy JSON access log with Grok and maps fields to the MITRE CAR schema before indexing into Elasticsearch.

## Tech Stack

- **OpenProject 16** (Ruby on Rails, PostgreSQL 13, Memcached)
- **Caddy 2** (reverse proxy with OpenTelemetry)
- **Gatling 3.10.3** (Scala load/attack simulations)
- **Elasticsearch 8.12.2 + Logstash + Filebeat + Kibana**
- **Jaeger 1.53** (distributed tracing, ES-backed storage)
