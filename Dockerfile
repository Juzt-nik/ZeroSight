# syntax=docker/dockerfile:1
# Target: IBM LinuxONE s390x (RHEL 9.8)
# Build: docker build -t privacy-native-vsoc .
# Runs backend (FastAPI) + Streamlit dashboard in one container for simplicity.
# For production on OpenShift, split into separate Deployments.

FROM python:3.11-slim

# s390x note: python:3.11-slim is available for s390x on Docker Hub.
# All pip packages listed below have s390x wheels or build from source on s390x.

WORKDIR /app

# System dependencies (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Application code
COPY . .

# Create data and models directories
RUN mkdir -p /app/data/raw /app/data/processed /app/models /app/data/synthetic

# Expose ports: 8000 = FastAPI backend, 8501 = Streamlit
EXPOSE 8000 8501

# Default command: start backend, then Streamlit
# In production, run these as separate containers.
CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port 8000 & streamlit run frontend/streamlit_app.py --server.port 8501 --server.address 0.0.0.0 --server.headless true"]