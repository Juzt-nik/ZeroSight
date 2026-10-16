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
| POST | `/detect` | analyst | Single frame inference |
| POST | `/detect/batch` | analyst | Batch inference |
| GET | `/detect/metrics` | analyst | Model metrics |

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

## Roles
- **analyst** — detection, tokenization, location coarsening
- **security_officer** — unmask approval/rejection
- **auditor** — audit queries, chain verification, anomaly warnings
- **admin** — all permissions (break-glass)

## Deny-by-Default
All endpoints require explicit permission. Missing or insufficient permissions return 403.