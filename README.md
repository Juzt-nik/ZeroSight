# Privacy-Native vSOC for Connected Vehicles

**IBM Z Datathon 2026 — AI Secured: Innovation Without Exposure**

A privacy-preserving Virtual Security Operations Center that detects cyberattacks
against connected vehicles using CAN-bus data while protecting driver identity
and precise location by default.

## Architecture

- **Backend:** FastAPI + Python 3.11
- **ML:** scikit-learn RandomForest (s390x-compatible)
- **Dashboard:** Streamlit
- **Database:** SQLite (hash-chained audit log)
- **Container:** Docker / docker-compose

## Repository Layout

```
privacy-native-vsoc/
├── backend/          # FastAPI app, routes, schemas, services
├── detection/        # CLI preprocessing, training, prediction, evaluation
├── privacy/          # Tokenization, location minimization, unmasking
├── access_control/   # RBAC policies, dual approval
├── audit/            # Hash-chained audit log, chain verification
├── anomaly_detection/# Threshold-based access anomaly rules
├── frontend/         # Streamlit dashboard
├── data/             # Dataset directory (populate with Car Hacking CSVs)
├── models/           # Trained model artifacts
├── scripts/          # seed_demo, verify_audit
├── tests/            # pytest suite
├── docs/             # Architecture, threat model, API, IBM Z mapping, demo
├── Dockerfile        # Container definition
├── compose.yaml      # Docker Compose orchestration
├── requirements.txt  # Python dependencies
└── README.md
```

## Quick Start (Docker)

```bash
# Clone the repository
git clone <your-repo-url>
cd privacy-native-vsoc

# Copy environment config
cp .env.example .env
# Edit .env with your secrets

# Copy dataset files to data/raw/ (you provide these)
cp /path/to/DoS_dataset.csv data/raw/
cp /path/to/Fuzzy_dataset.csv data/raw/
cp /path/to/gear_dataset.csv data/raw/
cp /path/to/RPM_dataset.csv data/raw/
cp /path/to/normal_run_data.txt data/raw/

# Build and run
docker compose up --build

# Backend: http://localhost:8000
# Dashboard: http://localhost:8501
# API docs: http://localhost:8000/docs
```

## Quick Start (Without Docker)

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy dataset files to data/raw/

# Start backend
uvicorn backend.main:app --host 0.0.0.0 --port 8000

# Start dashboard (separate terminal)
streamlit run frontend/streamlit_app.py --server.port 8501
```

## Running Tests

```bash
pytest tests/ -v
```

## Demo

See `docs/demo-script.md` for the 3-minute demonstration sequence.

## IBM Z Deployment

See `docs/ibm-z-mapping.md` for the honest IBM Z capability mapping.

**Important:** Running on IBM LinuxONE does not activate Secure Execution,
Crypto Express, or any other IBM Z capability. Those are documented integration
targets only.

## Limitations

- Model trained on HCRL Car Hacking research dataset; no real-world validation.
- Hash-chained audit log does not protect against a root DB admin rewriting
  the entire chain (external anchoring needed for full trust).
- No HSM or hardware-backed cryptography in this prototype.
- All demo data is synthetic; no real PII is used.