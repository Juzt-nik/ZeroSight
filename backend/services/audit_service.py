"""Tamper-evident hash-chained audit log.

Each record contains:
  hash = SHA-256(prev_hash || event_id || event_type || actor || outcome || details || timestamp)

Verification walks the chain and recomputes hashes. Any modification, deletion,
or reordering breaks the chain.

Limitation: Hash chaining detects tampering by non-privileged actors. A root
database administrator could rewrite the entire chain. For full trust, anchor
chain heads to external WORM storage or a SIEM.
"""

import os
import json
import hashlib
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)

logger = logging.getLogger("vsoc.audit")

CHECKPOINT_INTERVAL = int(os.getenv("AUDIT_CHECKPOINT_INTERVAL", "100"))
CHECKPOINT_KEY_PATH = os.getenv("AUDIT_CHECKPOINT_KEY_PATH", "./data/audit_checkpoint_key.pem")


class AuditService:
    def __init__(self, db_path: str = "./data/audit.db"):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    async def initialize(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                outcome TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '{}',
                timestamp TEXT NOT NULL,
                hash TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                sequence INTEGER PRIMARY KEY AUTOINCREMENT
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
                sequence INTEGER NOT NULL,
                hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                key_id TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        self._conn.commit()

        # Load or generate Ed25519 signing key for checkpoints
        self._checkpoint_key = self._load_or_create_checkpoint_key()

        count = self._conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        if count == 0:
            await self._write_genesis()

    async def _write_genesis(self):
        await self.log_event(
            event_type="system_startup",
            actor="system",
            outcome="success",
            details={"genesis": True},
        )

    def _load_or_create_checkpoint_key(self) -> Ed25519PrivateKey:
        """Load existing Ed25519 checkpoint key or generate a new one."""
        key_path = Path(CHECKPOINT_KEY_PATH)
        if key_path.exists():
            try:
                with open(key_path, "rb") as f:
                    key_data = f.read()
                from cryptography.hazmat.primitives.serialization import load_pem_private_key
                key = load_pem_private_key(key_data, password=None)
                if isinstance(key, Ed25519PrivateKey):
                    return key
            except Exception as exc:
                logger.warning("Failed to load checkpoint key: %s; generating new", exc)

        key = Ed25519PrivateKey.generate()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        pem = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        with open(key_path, "wb") as f:
            f.write(pem)
        logger.info("Generated new Ed25519 checkpoint key at %s", key_path)
        return key

    def _get_checkpoint_public_key_pem(self) -> str:
        """Return the public key PEM for checkpoint verification."""
        public_key = self._checkpoint_key.public_key()
        pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("utf-8")

    def _create_checkpoint(self, sequence: int, chain_hash: str) -> None:
        """Create a signed checkpoint at the given sequence."""
        key_id = "ed25519-v1"
        message = f"{sequence}|{chain_hash}".encode("utf-8")
        signature = self._checkpoint_key.sign(message)
        signature_hex = signature.hex()

        self._conn.execute(
            """
            INSERT INTO audit_checkpoints
            (sequence, hash, signature, key_id, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                sequence,
                chain_hash,
                signature_hex,
                key_id,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._conn.commit()
        logger.info("Created checkpoint at sequence %d", sequence)

    def _verify_checkpoint(
        self, sequence: int, chain_hash: str, signature_hex: str, key_id: str
    ) -> bool:
        """Verify a checkpoint signature independently."""
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            key_path = Path(CHECKPOINT_KEY_PATH)
            if not key_path.exists():
                return False
            with open(key_path, "rb") as f:
                key_data = f.read()
            key = load_pem_private_key(key_data, password=None)
            public_key = key.public_key()
            message = f"{sequence}|{chain_hash}".encode("utf-8")
            public_key.verify(bytes.fromhex(signature_hex), message)
            return True
        except Exception:
            return False

    def _compute_hash(
        self, prev_hash: str, event_id: str, event_type: str,
        actor: str, outcome: str, details: Dict[str, Any], timestamp: str
    ) -> str:
        payload = (
            f"{prev_hash}|{event_id}|{event_type}|{actor}|{outcome}|"
            f"{json.dumps(details, sort_keys=True)}|{timestamp}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _get_last_hash(self) -> str:
        row = self._conn.execute(
            "SELECT hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else "0" * 64

    async def log_event(
        self,
        event_type: str,
        actor: str,
        outcome: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        if self._conn is None:
            raise RuntimeError("Audit service not initialized")
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        prev_hash = self._get_last_hash()
        details = details or {}
        hash_value = self._compute_hash(
            prev_hash, event_id, event_type, actor, outcome, details, timestamp
        )
        self._conn.execute(
            """
            INSERT INTO audit_events
            (event_id, event_type, actor, outcome, details, timestamp, hash, prev_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, event_type, actor, outcome, json.dumps(details, sort_keys=True),
             timestamp, hash_value, prev_hash),
        )
        self._conn.commit()
        logger.debug("Audit event logged: %s %s %s", event_type, actor, outcome)

        # P2-01: Create periodic signed checkpoint
        seq = self._conn.execute(
            "SELECT sequence FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()[0]
        if seq % CHECKPOINT_INTERVAL == 0:
            last_hash = self._get_last_hash()
            self._create_checkpoint(seq, last_hash)

        return event_id

    def get_events(
        self,
        event_type: Optional[str] = None,
        actor: Optional[str] = None,
        outcome: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        if self._conn is None:
            raise RuntimeError("Audit service not initialized")
        query = "SELECT event_id, event_type, actor, outcome, details, timestamp, hash, prev_hash, sequence FROM audit_events WHERE 1=1"
        params: List[Any] = []
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if actor:
            query += " AND actor = ?"
            params.append(actor)
        if outcome:
            query += " AND outcome = ?"
            params.append(outcome)
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)
        query += " ORDER BY sequence DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self._conn.execute(query, params).fetchall()
        return [
            {
                "event_id": r[0],
                "event_type": r[1],
                "actor": r[2],
                "outcome": r[3],
                "details": json.loads(r[4]),
                "timestamp": r[5],
                "hash": r[6],
                "prev_hash": r[7],
                "sequence": r[8],
            }
            for r in rows
        ]

    def verify_chain(self) -> Dict[str, Any]:
        if self._conn is None:
            raise RuntimeError("Audit service not initialized")
        rows = self._conn.execute(
            "SELECT event_id, event_type, actor, outcome, details, timestamp, hash, prev_hash, sequence FROM audit_events ORDER BY sequence ASC"
        ).fetchall()
        total = len(rows)
        if total == 0:
            return {
                "chain_valid": True,
                "total_records": 0,
                "verified_records": 0,
                "first_hash": "",
                "last_hash": "",
                "tampered_records": [],
                "message": "Empty chain",
            }
        verified = 0
        tampered: List[str] = []
        expected_prev = "0" * 64
        for r in rows:
            event_id, event_type, actor, outcome, details_json, timestamp, stored_hash, stored_prev, seq = r
            details = json.loads(details_json)
            computed_hash = self._compute_hash(
                stored_prev, event_id, event_type, actor, outcome, details, timestamp
            )
            prev_ok = (stored_prev == expected_prev)
            hash_ok = (stored_hash == computed_hash)
            if not prev_ok or not hash_ok:
                tampered.append(event_id)
                logger.warning("Tampered record detected: %s", event_id)
            else:
                verified += 1
            expected_prev = stored_hash
        first_hash = rows[0][6]
        last_hash = rows[-1][6]
        chain_valid = len(tampered) == 0
        return {
            "chain_valid": chain_valid,
            "total_records": total,
            "verified_records": verified,
            "first_hash": first_hash,
            "last_hash": last_hash,
            "tampered_records": tampered,
            "message": (
                "Chain is valid" if chain_valid
                else f"Chain compromised: {len(tampered)} tampered record(s)"
            ),
        }

    def verify_checkpoints(self) -> Dict[str, Any]:
        """Verify all signed checkpoint signatures independently."""
        if self._conn is None:
            raise RuntimeError("Audit service not initialized")
        rows = self._conn.execute(
            "SELECT sequence, hash, signature, key_id FROM audit_checkpoints ORDER BY sequence ASC"
        ).fetchall()
        total = len(rows)
        if total == 0:
            return {
                "checkpoints_valid": True,
                "total_checkpoints": 0,
                "verified_checkpoints": 0,
                "failed_checkpoints": [],
                "message": "No checkpoints",
            }
        verified = 0
        failed: List[str] = []
        for seq, chain_hash, signature_hex, key_id in rows:
            if self._verify_checkpoint(seq, chain_hash, signature_hex, key_id):
                verified += 1
            else:
                failed.append(str(seq))
        all_valid = len(failed) == 0
        return {
            "checkpoints_valid": all_valid,
            "total_checkpoints": total,
            "verified_checkpoints": verified,
            "failed_checkpoints": failed,
            "message": (
                "All checkpoints valid"
                if all_valid
                else f"{len(failed)} checkpoint(s) failed verification"
            ),
        }

    def count(self) -> int:
        if self._conn is None:
            return 0
        return self._conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]


# Module-level singleton instance (initialized in main.py lifespan)
audit_service = AuditService()