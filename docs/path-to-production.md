# Path to Production — ZeroSight Privacy-Native vSOC

This document lists each major blueprint component, its current demo
implementation, the IBM Z/production target, status, security/operational gaps,
owner, and evidence pointer. This satisfies Blueprint §6.3–§6.5, §9, and
Appendix A/D requirements.

**Status key:** `implemented` | `stand-in` | `documented` | `missing` | `deferred`

---

## Component Status Table

| Component | Current Demo Implementation | IBM Z / Production Target | Status | Gaps | Owner | Evidence |
|-----------|---------------------------|---------------------------|--------|------|-------|----------|
| Trusted execution zone | Isolated Docker container network | Secure Execution for Linux | stand-in | No hardware-enforced memory isolation; container escape risk | Platform | `Dockerfile`, `compose.yaml` |
| Key vault | SoftHSM / file-based key storage | Crypto Express HSM | stand-in | No HSM-backed key protection; keys on disk | Security | `backend/services/tokenization.py` |
| Data at rest | SQLite with AES-256-GCM (via OS) | Linux on Z disk encryption with protected keys | stand-in | No transparent data encryption configured | Platform | `backend/services/audit_service.py` |
| Crypto scanner | Custom scanner emitting CycloneDX CBOM | Guardium Quantum Safe | implemented | Limited to declared config inventory; not comprehensive | Security | `scripts/crypto_scanner.py` |
| SIEM | CEF/syslog output (documented) | QRadar | documented | Not yet integrated | Operations | `docs/architecture.md` |
| Orchestration | Docker Compose | OpenShift on IBM Z | stand-in | No K8s manifests; single-node only | Platform | `compose.yaml` |
| ML model | RandomForest (scikit-learn) | XGBoost + Isolation Forest | stand-in | Ensemble behind `USE_ENSEMBLE` flag; not default | ML | `backend/services/model_service.py` |
| CAN bus interface | File-based dataset replay | Real CAN bus hardware interface | missing | No live vehicle integration | ML | `scripts/replay.py` |
| Authentication | JWT / demo bearer tokens | OIDC / Keycloak integration | implemented | Production JWT path requires PyJWT + AUTH_SECRET | Security | `backend/auth.py` |
| Access control | In-memory RBAC | OPA / external policy engine | stand-in | No dynamic policy updates | Security | `backend/services/access_control.py` |
| Audit log | Hash-chained SQLite | External WORM anchoring | implemented | Checkpoints exist but not externally anchored | Security | `backend/services/audit_service.py` |
| Unmasking | Dual-approval in-memory | HSM-backed dual approval | implemented | Identity map in memory; not persisted across restarts | Security | `backend/services/unmasking.py` |
| Dashboard | Streamlit | Enterprise SIEM dashboard | stand-in | No SSO; no role-based view restrictions | Frontend | `frontend/streamlit_app.py` |

---

## Stand-In Summary

| Stand-In | Replacement Path | Production Blocker |
|----------|-----------------|-------------------|
| Docker container | Secure Execution for Linux | Requires IBM Z firmware/hypervisor support |
| File-based key storage | Crypto Express HSM | Requires HSM hardware and key management integration |
| SQLite | Encrypted volumes with protected keys | Requires TDE configuration on Linux on Z |
| RandomForest | XGBoost + Isolation Forest | `USE_ENSEMBLE=true` needed; XGBoost not in requirements |
| In-memory RBAC | OPA / Keycloak | Requires external identity provider |
| Local checkpoints | External WORM anchoring | Requires external storage integration |

---

## Measured Results

No load-test results have been recorded against integrated endpoints yet.
Run `python tests/load/loadtest.py` against a deployed instance to generate
baseline throughput and latency measurements.

---

## Claims Discipline

- Identity and location are hidden from analysts by default (pseudonymized tokens, coarsened GPS)
- Unmasking is gated by dual approval and audited
- Plaintext exists only inside the trusted processing boundary
- **Not claimed:** total anonymity, production readiness, actual IBM Z execution, or cross-vehicle generalization without evidence

---

## Deferred Items

| Item | Reason |
|------|--------|
| P2-02 comprehensive endpoint scanning | Scanner limited to declared config inventory |
| P2-03 load test results | Requires deployed instance |
| HSM-backed key management | Hardware dependency |
| Secure Execution for Linux | IBM Z hardware dependency |