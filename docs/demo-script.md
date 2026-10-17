# Seven-Scene Demo and Exact Run Commands

The dashboard sends a bearer token on each protected request and displays the
principal returned by `/access/me`. In demo mode use tokens such as
`analyst_1:analyst`, `sec_officer_1:security_officer`, and `auditor_1:auditor`.
Use backend-issued JWTs outside demo mode.

## Repeatable local run (PowerShell)

From the repository root, create the environment once:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:DEMO_MODE = "true"
$env:AUTH_SECRET = "local-demo-auth-secret-0123456789"
$env:TOKEN_SECRET = "local-demo-token-secret-0123456789"
```

Put the required dataset files in `data/raw/` before first startup. The backend
trains a baseline if no model artifact exists.

Terminal 1:

```powershell
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Terminal 2, in the same activated environment:

```powershell
$env:BACKEND_URL = "http://localhost:8000"
streamlit run frontend/streamlit_app.py --server.port 8501
```

Open `http://localhost:8501`. Switch to the second security-officer token for
unmask approval. Use an auditor token for audit and anomaly scenes. The audit
tamper action changes a database row; use a disposable demo database.

## Authenticated end-to-end/load run

```powershell
$env:VSOC_API_TOKEN = "load_runner:analyst"
python tests/load/loadtest.py --url http://localhost:8000 --frames 1000 --concurrency 10 --output load_test_results.json
```

For per-attack accuracy and false-positive rate, supply JSONL cases containing
actual ground-truth labels, one case per line:

```json
{"frame":{"timestamp":1.0,"arbitration_id":"0316","dlc":8,"data_bytes":[5,33,104,9,33,33,0,111]},"label":"Normal"}
```

```powershell
python tests/load/loadtest.py --url http://localhost:8000 --token $env:VSOC_API_TOKEN --input .\data\demo-cases.jsonl --concurrency 10 --output load_test_results.json
```

The runner targets authenticated `POST /detect`. It reports server inference
latency separately from client HTTP round-trip latency, throughput, errors,
per-label metrics, and false-positive rate on ground-truth `Normal` cases. The
generated default probe is unlabeled, so it does not claim classification
quality. Preserve the JSON output as evidence for the actual deployment run.

## Seven scenes

1. **Detect CAN attack:** submit a frame; show prediction, confidence, inference time, and the audit provenance metadata.
2. **Tokenize vehicle:** pseudonymize a synthetic vehicle identifier.
3. **Minimize location:** coarsen or withhold sample coordinates.
4. **Request unmask:** submit a request as security officer one.
5. **Approve unmask:** switch to a distinct officer and approve or reject.
6. **Audit and anomalies:** record events for the authenticated account, load warnings, and verify the chain. Tamper testing is destructive to the disposable audit database.
7. **Metrics and load:** show model metrics and the saved load report.

All seven scenes use implemented backend routes. No scene is intentionally
omitted. Live CAN hardware, external identity providers, and IBM Z security
hardware are not active features of this demo.

## Three-minute narration

- **0:00–0:20 — Story:** introduce privacy-preserving connected-vehicle security; all inputs are synthetic.
- **0:20–0:45 — Detection:** show prediction, confidence, server inference time, and model/feature-schema provenance.
- **0:45–1:10 — Privacy:** tokenize a synthetic ID and minimize sample coordinates.
- **1:10–1:40 — Unmask:** request with officer one, then approve with a distinct officer.
- **1:40–2:20 — Audit/anomaly:** record denial events for the signed-in auditor, show warnings, and verify audit integrity.
- **2:20–2:45 — Metrics:** show model metrics and the load report; distinguish inference from network round-trip time.
- **2:45–3:00 — Deployment truth:** Secure Execution, Crypto Express, and OpenShift remain targets unless actually deployed.

## Fallback recording

Capture one clean run of these seven scenes and save it as `docs/fallback-demo.mp4`
or the team's chosen media location. Hide the bearer token and use synthetic
identifiers only. Keep the corresponding `load_test_results.json` with it. The
recording has not yet been captured in this repository.
