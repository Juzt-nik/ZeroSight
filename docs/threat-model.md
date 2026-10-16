# Threat Model

## Assets
- CAN bus telemetry data
- ML detection model
- Pseudonymous vehicle tokens
- Identity mapping (token → real VIN)
- Audit log

## Threat Actors
1. **External attacker** — injects malicious CAN frames
2. **Malicious insider (analyst)** — attempts to view raw identity/location
3. **Compromised security officer** — attempts unilateral unmasking
4. **Privileged DB admin** — could rewrite audit chain (mitigated by external anchoring)

## Mitigations
| Threat | Mitigation |
|--------|-----------|
| CAN bus attack | ML detection (RandomForest) + alerting |
| Identity exposure | Pseudonymous tokens, HMAC-based, key rotation |
| Location exposure | Coarsening / withholding by policy |
| Unauthorized unmask | Dual approval, distinct approvers, deny-by-default RBAC |
| Audit tampering | Hash-chained log + verification endpoint |
| Replay attacks | Nonce + TTL on unmask requests |

## Limitations
- Hash chaining does not prevent a root DB admin from rewriting the entire chain.
- No hardware security module (HSM) integration in this prototype.
- Model trained on research dataset; not validated on production vehicles.