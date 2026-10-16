# 3-Minute Demo Script

## Sequence

### 0:00–0:30 — Introduction
- Show the running application on IBM LinuxONE (RHEL 9.8).
- Explain the project: privacy-native vSOC for connected vehicles.
- Highlight: attack detection + privacy by default.

### 0:30–1:00 — CAN-bus Attack Detection
- Load synthetic CAN traffic.
- Submit a frame via the Detection page.
- Show attack prediction (e.g., DoS) with confidence score.
- Note: alert is generated with a **pseudonymous vehicle token**, not a real VIN.

### 1:00–1:30 — Privacy Protections
- Tokenize page: show how a real VIN becomes a 16-char token.
- Location Minimization page: show coordinates coarsened to grid cell or withheld.
- Emphasize: ordinary analysts cannot see raw identity or precise GPS.

### 1:30–2:15 — Dual-Approval Unmasking
- Attempt unmasking as a single security officer → show it's pending (needs 2nd approval).
- Attempt duplicate approval by same officer → show rejection.
- Complete unmasking with two **distinct** security officers → show identity revealed.
- Attempt unauthorized unmasking as analyst → show 403 denial.

### 2:15–2:45 — Tamper-Evident Audit
- Audit Log page: show chain of events (alerts, denials, unmask requests, approvals).
- Click "Verify Chain Integrity" → show valid chain.
- Click "Test Tamper Detection" → show chain compromised detected.
- Explain: hash chaining detects modification by non-privileged actors.

### 2:45–3:00 — IBM Z Deployment
- Show the application running on the LinuxONE VM.
- Explain the honest IBM Z mapping: app runs on s390x/RHEL 9.8;
  Secure Execution, Crypto Express, OpenShift are documented integration targets,
  not active features.

## Demo Data
All data is synthetic. No real PII or vehicle telemetry is used.