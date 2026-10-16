# Architecture

## Overview
Privacy-native vSOC for Connected Vehicles — a FastAPI backend with Streamlit dashboard,
running on IBM LinuxONE (RHEL 9.8, s390x).

## Components

```
┌─────────────┐      ┌──────────────┐      ┌─────────────────┐
│  Streamlit  │◄────►│  FastAPI     │◄────►│  SQLite (audit) │
│  Dashboard  │      │  Backend     │      │  (models)       │
└─────────────┘      └──────┬───────┘      └─────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │ Detection│    │ Privacy  │    │ Access   │
    │ Service  │    │ Service  │    │ Control  │
    └──────────┘    └──────────┘    └──────────┘
          │                │                │
          ▼                ▼                ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │ Random   │    │ Tokenize │    │ RBAC +   │
    │ Forest   │    │ Location │    │ Dual     │
    │ Model    │    │ Coarsen  │    │ Approval │
    └──────────┘    └──────────┘    └──────────┘
```

## Data Flow
1. CAN bus frame received via `/detect` endpoint.
2. Preprocessing extracts features (timestamp delta, DLC, byte entropy, etc.).
3. RandomForest model predicts attack class.
4. If attack detected, audit event logged with pseudonymous vehicle token.
5. Dashboard displays masked alerts (no raw identity, no precise location).
6. Unmasking requires two distinct security officer approvals.
7. All events written to hash-chained audit log.

## Honest IBM Z Positioning
- **Implemented/tested:** FastAPI, Streamlit, SQLite, scikit-learn on RHEL 9.8 s390x.
- **Documented target:** Secure Execution for Linux, Crypto Express/HSM, OpenShift, QRadar CEF/syslog.
- **Not claimed active:** Any IBM Z-specific hardware feature merely because code runs on LinuxONE.