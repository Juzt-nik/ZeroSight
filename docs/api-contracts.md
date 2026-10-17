# API Contracts

## Base URL
`http://localhost:8000`

## Endpoints

### System
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | none | Health check |
| GET | `/` | none | Service info |

### Detection
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/detect` | analyst | Legacy single-frame inference |
| POST | `/detect/window` | analyst | One prediction from all frames in one bounded time window |
| POST | `/detect/batch` | analyst | Legacy per-frame batch inference |
| GET | `/detect/metrics` | analyst | Model metrics |

Detection responses include `inference_latency_ms`, the server-side duration
of the `predict_window` call in milliseconds. It excludes request/network
overhead and includes any wait for the model's inference lock.
Attack audit events include `model_version` and `feature_schema_version`
(`can-window-v1`) for model and feature provenance.

### Privacy
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/privacy/tokenize` | analyst | Generate pseudonymous token |
| POST | `/privacy/location/coarsen` | analyst | Apply location minimization |
| POST | `/privacy/unmask/request` | security_officer | Request unmask |
| POST | `/privacy/unmask/approve` | security_officer | Approve/reject unmask |
| GET | `/privacy/unmask/requests` | security_officer, auditor | List requests |

### Access
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/access/roles` | auditor | List roles |
| GET | `/access/me` | analyst | Current user info |

### Audit
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/audit/events` | auditor | Query audit events |
| GET | `/audit/verify` | auditor | Verify chain integrity |
| POST | `/audit/verify/tamper` | auditor | Test tamper detection |

### Anomaly
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/anomaly/warnings` | auditor | Access anomaly warnings |
| POST | `/anomaly/record-event?user_id=...&action=...&outcome=...` | auditor | Record a caller's own demo access event |

The record-event route requires `user_id` to match the authenticated principal;
attempts to attribute events to another account return 403. Persisted security
events also feed anomaly monitoring from the audit event listener. On startup,
the most recent 10,000 audit events are replayed into the in-memory detector so
warnings survive a service restart (within that replay window). Manual demo
events are inserted into the detector once and are not double-counted by the
audit listener.

## Roles
- **analyst** — detection, tokenization, location coarsening
- **security_officer** — unmask approval/rejection
- **auditor** — audit queries, chain verification, anomaly warnings
- **admin** — all permissions (break-glass)

## Deny-by-Default
All endpoints require explicit permission. Missing or insufficient permissions return 403.
