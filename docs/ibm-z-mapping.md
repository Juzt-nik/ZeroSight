# IBM Z Capability Mapping

This document distinguishes between:
1. **Implemented and tested** on the LinuxONE VM
2. **Simulated in application code** (interfaces/stubs only)
3. **Documented as possible production integration**

## Deployment Platform

| Capability | Status | Notes |
|------------|--------|-------|
| LinuxONE / s390x | **Implemented** | Target deployment: RHEL 9.8, 3 vCPU, 8 GB RAM |
| Container (Docker/Podman) | **Implemented** | Dockerfile and compose.yaml provided |
| OpenShift on IBM Z | **Documented** | Production path; not configured in this prototype |

## Trusted Execution & Cryptography

| Capability | Status | Notes |
|------------|--------|-------|
| Secure Execution for Linux | **Simulated** | Code has no dependency; documented as target |
| Crypto Express / HSM keys | **Simulated** | Python `cryptography` used; key mgmt interface exists |
| Platform/storage encryption | **Documented** | RHEL 9.8 LUKS/dm-crypt recommended; not configured by app |
| Quantum-safe readiness | **Documented** | CycloneDX SBOM relationship documented; no PQ crypto in app |

## SIEM Integration

| Capability | Status | Notes |
|------------|--------|-------|
| CEF/syslog export | **Documented** | Audit events could be exported; not implemented |
| QRadar integration | **Documented** | Integration point only |

## Architecture Honesty Statement
Running this application on LinuxONE does **not** mean Secure Execution, Crypto Express,
or any other IBM Z capability is active. Those require separate configuration, hardware,
and entitlements. This prototype implements the application layer; IBM Z infrastructure
mapping is documented for production planning.

## s390x Compatibility
- Python 3.11: available for s390x
- scikit-learn: pip wheel available for s390x
- FastAPI/uvicorn: pure Python, s390x-compatible
- Streamlit: pure Python, s390x-compatible
- XGBoost: not used (no reliable s390x wheel); RandomForest used instead