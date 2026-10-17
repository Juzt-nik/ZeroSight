# ZeroSight Threat Model

## Purpose and security objective

ZeroSight is a privacy-preserving virtual Security Operations Center (vSOC) for connected vehicles. It should detect suspicious CAN-bus activity while keeping driver identity and precise location hidden during ordinary alert handling.

## Assets

- CAN-bus telemetry and attack-detection results
- Trained ML model and model artifacts
- Pseudonymous vehicle tokens
- Identity mapping from a token to a real vehicle identity
- Location data, including precise coordinates
- User identities, role assignments, and demo authentication tokens
- Unmask requests, approval decisions, and the audit log

## Trust boundaries

1. **Vehicle/data-ingestion boundary:** incoming telemetry and vehicle-provided fields must be treated as untrusted.
2. **API boundary:** callers are untrusted until authenticated; client-supplied user IDs are not proof of identity.
3. **Authorization boundary:** role and permission checks must be enforced by backend services as well as routes for sensitive operations.
4. **Identity-mapping boundary:** the mapping between pseudonymous token and real identity must remain separate from ordinary detection and alert responses.
5. **Audit-storage boundary:** a hash chain detects many edits but is not independently protected from a privileged attacker who can rewrite the whole database and chain.
6. **Deployment boundary:** running on IBM LinuxONE does not by itself mean Secure Execution, Crypto Express, an HSM, QRadar, or quantum-safe TLS is enabled.

## Threat actors

1. **External attacker:** injects or replays malicious CAN frames, or attempts to call APIs without valid credentials.
2. **Malicious analyst:** tries to obtain identity or precise location beyond their role.
3. **Compromised or malicious security officer:** attempts to approve their own request, repeat an approval, or unmask unilaterally.
4. **Misconfigured administrator:** assumes admin permissions should count as a second security-officer approval.
5. **Privileged database administrator:** tampers with or rewrites audit records.
6. **Malicious API caller:** supplies a fake `requested_by` or `approver_user_id` field to impersonate another principal.

## Threats and mitigations

| Threat | Required control | Verification |
|---|---|---|
| Forged caller identity | Use authenticated Bearer principal; never trust IDs in request JSON | A caller-supplied security-officer ID cannot elevate an analyst |
| Unauthorized sensitive operation | Deny-by-default RBAC and exact role checks | Analyst and auditor cannot approve or unmask |
| Administrator bypasses dual control | Admin wildcard permissions do not imply the `security_officer` role | Admin cannot act as a security-officer approver unless separately and explicitly assigned that role |
| Single-person unmasking | Require at least two distinct, registered security officers; requester cannot approve their own request | Same user twice and requester self-approval are rejected |
| Repeated or replayed approval | Request state machine, duplicate-approver rejection, expiry, and single-use disclosure | Completed, rejected, expired, duplicate, or replayed operation fails |
| Concurrent approval race | Serialize in-process state transitions; use transactional storage/locking in production | Simultaneous approval attempts cannot count one approver twice |
| Expired request | Enforce request TTL during read/approval/rejection | Expired request transitions to expired and cannot be approved |
| Identity leakage in normal workflow | Return masked identity by default; expose identity only after dual approval and once | Ordinary requests and request listings always return `real_identity: null` |
| Access abuse | Log denials and approval events; alert on repeated suspicious actions | Repeated-denial tests raise an anomaly warning |
| Audit record tampering | Hash-chained records and verification | Modified/reordered records cause verification failure |
| Audit truncation or full rewrite | Anchor chain head outside the database or use protected external storage | Documented limitation unless an external anchor is actually implemented |
| Weak or duplicated demo tokens | Require high-entropy tokens and reject duplicated configured tokens | Missing, weak, duplicated, or invalid token configuration fails closed |
| Raw location exposure | Coarsen or withhold location according to policy; minimize logs | API outputs and logs do not expose precise coordinates by default |

## Authorization rules

- **Analyst:** detection and permitted privacy minimization actions; cannot request or approve unmasking under the current prototype policy.
- **Security officer:** may create unmask requests and approve/reject requests; requester cannot approve their own request.
- **Auditor:** may view/verify audit information but cannot approve unmasking merely because they are an auditor.
- **Admin:** has wildcard application permissions for documented break-glass operations, but admin status does not implicitly count as the `security_officer` role in the dual-approval workflow.
- Unknown users, unknown roles, missing authentication, and invalid permissions are denied.

## Authentication scope and limitations

The Step 2 implementation provides environment-configured Bearer tokens for a **local demonstration only**. Demo authentication must be explicitly enabled, tokens must be unique and high-entropy, and secrets must not be committed. It is not a replacement for production OIDC/OAuth2, signed identity tokens, centralized revocation, secure secret distribution, or a trusted identity provider. The unmask request store and identity mapping remain in memory and do not survive application restart; production needs transactional persistence and access-isolated identity storage.

## IBM Z mapping

LinuxONE is the deployment target. Secure Execution for Linux, Crypto Express/HSM-backed keys, storage encryption, SIEM export, OpenShift on IBM Z, and quantum-safe cryptographic mechanisms are integration targets unless separately configured and verified. Do not claim these are active solely because the application runs on LinuxONE.

## Acceptance criteria

- Anonymous privacy endpoints are rejected when no trusted identity provider is configured.
- Invalid or unknown Bearer tokens are rejected.
- User IDs in JSON do not influence authorization decisions.
- Admin wildcard permission does not silently satisfy explicit security-officer role checks.
- Unmasking requests require valid justification, have an expiry, and need two distinct authorized approvers.
- Requester self-approval, duplicate approvals, unauthorized approvals, expired approvals, and reuse of identity disclosure are rejected.
- Identity is absent from routine alert/request-list responses.
- Audit and access-anomaly controls are covered by automated tests.
