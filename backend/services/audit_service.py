"""Tamper-evident hash-chained audit log.

Each record contains:
    hash = SHA-256(
        prev_hash || event_id || event_type || actor ||
        outcome || details || timestamp
    )

Verification recomputes hashes and checks chain links. Signed checkpoints
provide an additional integrity check for periodic audit-log positions.

Limitation:
    Hash chains and checkpoints stored in the same database cannot fully
    protect against an administrator who can rewrite both. For stronger
    guarantees, anchor checkpoint hashes in independently controlled WORM
    storage or a SIEM.
"""

import os
import json
import hashlib
import logging
import sqlite3
import uuid

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

logger = logging.getLogger("vsoc.audit")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CHECKPOINT_INTERVAL = int(os.getenv("AUDIT_CHECKPOINT_INTERVAL", "100"))

if CHECKPOINT_INTERVAL < 1:
    raise ValueError(
        "AUDIT_CHECKPOINT_INTERVAL must be a positive integer"
    )

CHECKPOINT_KEY_PATH = os.getenv(
    "AUDIT_CHECKPOINT_KEY_PATH",
    "./data/audit_checkpoint_key.pem",
)


# ---------------------------------------------------------------------------
# Audit service
# ---------------------------------------------------------------------------

class AuditService:
    def __init__(self, db_path: str = "./data/audit.db"):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._checkpoint_key: Optional[Ed25519PrivateKey] = None

    async def initialize(self):
        """Initialize the database, checkpoint key, and genesis event."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")

        self._conn.execute(
            """
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
            """
        )

        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
                sequence INTEGER NOT NULL,
                hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                key_id TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )

        self._conn.commit()

        self._checkpoint_key = self._load_or_create_checkpoint_key()

        count = self._conn.execute(
            "SELECT COUNT(*) FROM audit_events"
        ).fetchone()[0]

        if count == 0:
            await self._write_genesis()

    async def _write_genesis(self):
        """Write the first event into an empty audit chain."""
        await self.log_event(
            event_type="system_startup",
            actor="system",
            outcome="success",
            details={"genesis": True},
        )

    # -----------------------------------------------------------------------
    # Checkpoint key management
    # -----------------------------------------------------------------------

    def _load_or_create_checkpoint_key(self) -> Ed25519PrivateKey:
        """Load an existing Ed25519 key or generate a new one."""
        key_path = Path(CHECKPOINT_KEY_PATH)

        if key_path.exists():
            try:
                from cryptography.hazmat.primitives.serialization import (
                    load_pem_private_key,
                )

                with key_path.open("rb") as key_file:
                    key_data = key_file.read()

                key = load_pem_private_key(
                    key_data,
                    password=None,
                )

                if isinstance(key, Ed25519PrivateKey):
                    return key

                raise ValueError(
                    "Checkpoint key is not an Ed25519 private key"
                )

            except Exception as exc:
                # Do not silently replace a key that may be needed to
                # verify existing checkpoints. Losing the original key
                # can make previously signed checkpoints unverifiable.
                raise RuntimeError(
                    f"Could not load audit checkpoint key at {key_path}"
                ) from exc

        key = Ed25519PrivateKey.generate()

        key_path.parent.mkdir(parents=True, exist_ok=True)

        pem = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )

        # Create the key exclusively so an existing file is not overwritten.
        try:
            with key_path.open("xb") as key_file:
                key_file.write(pem)
        except FileExistsError:
            # Another process may have created the key concurrently.
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key,
            )

            with key_path.open("rb") as key_file:
                existing_data = key_file.read()

            existing_key = load_pem_private_key(
                existing_data,
                password=None,
            )

            if not isinstance(existing_key, Ed25519PrivateKey):
                raise RuntimeError(
                    "Existing audit checkpoint key is not an Ed25519 key"
                )

            return existing_key

        logger.info(
            "Generated a new Ed25519 audit checkpoint key"
        )
        return key

    def _get_checkpoint_public_key_pem(self) -> str:
        """Return the checkpoint verification public key as PEM."""
        if self._checkpoint_key is None:
            raise RuntimeError("Audit service checkpoint key not initialized")

        public_key = self._checkpoint_key.public_key()

        pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )

        return pem.decode("utf-8")

    # -----------------------------------------------------------------------
    # Signed checkpoints
    # -----------------------------------------------------------------------

    def _create_checkpoint(
        self,
        sequence: int,
        chain_hash: str,
    ) -> None:
        """Create a signed checkpoint for an audit-chain position."""
        if self._conn is None:
            raise RuntimeError("Audit service not initialized")

        if self._checkpoint_key is None:
            raise RuntimeError("Audit service checkpoint key not initialized")

        key_id = "ed25519-v1"
        message = f"{sequence}|{chain_hash}".encode("utf-8")
        signature_hex = self._checkpoint_key.sign(message).hex()

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

        logger.info(
            "Created audit checkpoint at sequence %d",
            sequence,
        )

    def _verify_checkpoint(
        self,
        sequence: int,
        chain_hash: str,
        signature_hex: str,
        key_id: str,
    ) -> bool:
        """Verify a checkpoint signature using the configured public key."""
        if key_id != "ed25519-v1":
            return False

        try:
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key,
            )

            key_path = Path(CHECKPOINT_KEY_PATH)

            if not key_path.exists():
                return False

            with key_path.open("rb") as key_file:
                key_data = key_file.read()

            key = load_pem_private_key(
                key_data,
                password=None,
            )

            if not isinstance(key, Ed25519PrivateKey):
                return False

            public_key = key.public_key()
            message = f"{sequence}|{chain_hash}".encode("utf-8")

            public_key.verify(
                bytes.fromhex(signature_hex),
                message,
            )

            return True

        except Exception:
            return False

    # -----------------------------------------------------------------------
    # Hash-chain operations
    # -----------------------------------------------------------------------

    def _compute_hash(
        self,
        prev_hash: str,
        event_id: str,
        event_type: str,
        actor: str,
        outcome: str,
        details: Dict[str, Any],
        timestamp: str,
    ) -> str:
        """Compute the SHA-256 hash of an event."""
        payload = (
            f"{prev_hash}|{event_id}|{event_type}|{actor}|{outcome}|"
            f"{json.dumps(details, sort_keys=True)}|{timestamp}"
        )

        return hashlib.sha256(
            payload.encode("utf-8")
        ).hexdigest()

    def _get_last_hash(self) -> str:
        """Return the most recent event hash, or the genesis predecessor."""
        if self._conn is None:
            raise RuntimeError("Audit service not initialized")

        row = self._conn.execute(
            """
            SELECT hash
            FROM audit_events
            ORDER BY sequence DESC
            LIMIT 1
            """
        ).fetchone()

        return row[0] if row else "0" * 64

    async def log_event(
        self,
        event_type: str,
        actor: str,
        outcome: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Append an event to the audit chain and create checkpoints."""
        if self._conn is None:
            raise RuntimeError("Audit service not initialized")

        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        prev_hash = self._get_last_hash()
        event_details = details if details is not None else {}

        hash_value = self._compute_hash(
            prev_hash,
            event_id,
            event_type,
            actor,
            outcome,
            event_details,
            timestamp,
        )

        self._conn.execute(
            """
            INSERT INTO audit_events (
                event_id,
                event_type,
                actor,
                outcome,
                details,
                timestamp,
                hash,
                prev_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                event_type,
                actor,
                outcome,
                json.dumps(event_details, sort_keys=True),
                timestamp,
                hash_value,
                prev_hash,
            ),
        )
        self._conn.commit()

        logger.debug(
            "Audit event logged: %s %s %s",
            event_type,
            actor,
            outcome,
        )

        sequence = self._conn.execute(
            """
            SELECT sequence
            FROM audit_events
            ORDER BY sequence DESC
            LIMIT 1
            """
        ).fetchone()[0]

        if sequence % CHECKPOINT_INTERVAL == 0:
            self._create_checkpoint(
                sequence,
                self._get_last_hash(),
            )

        return event_id

    # -----------------------------------------------------------------------
    # Event queries
    # -----------------------------------------------------------------------

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
        """Query audit events with optional filters and pagination."""
        if self._conn is None:
            raise RuntimeError("Audit service not initialized")

        query = """
            SELECT
                event_id,
                event_type,
                actor,
                outcome,
                details,
                timestamp,
                hash,
                prev_hash,
                sequence
            FROM audit_events
            WHERE 1=1
        """
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

        rows = self._conn.execute(
            query,
            params,
        ).fetchall()

        events: List[Dict[str, Any]] = []

        for row in rows:
            try:
                event_details = json.loads(row[4])
            except (json.JSONDecodeError, TypeError):
                event_details = None

            events.append(
                {
                    "event_id": row[0],
                    "event_type": row[1],
                    "actor": row[2],
                    "outcome": row[3],
                    "details": event_details,
                    "timestamp": row[5],
                    "hash": row[6],
                    "prev_hash": row[7],
                    "sequence": row[8],
                }
            )

        return events

    # -----------------------------------------------------------------------
    # Chain verification
    # -----------------------------------------------------------------------

    def verify_chain(self) -> Dict[str, Any]:
        """Verify stored event hashes and predecessor links."""
        if self._conn is None:
            raise RuntimeError("Audit service not initialized")

        rows = self._conn.execute(
            """
            SELECT
                event_id,
                event_type,
                actor,
                outcome,
                details,
                timestamp,
                hash,
                prev_hash,
                sequence
            FROM audit_events
            ORDER BY sequence ASC
            """
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

        for row in rows:
            (
                event_id,
                event_type,
                actor,
                outcome,
                details_json,
                timestamp,
                stored_hash,
                stored_prev,
                sequence,
            ) = row

            try:
                details = json.loads(details_json)

                if not isinstance(details, dict):
                    raise ValueError("Audit details must be a JSON object")

                computed_hash = self._compute_hash(
                    stored_prev,
                    event_id,
                    event_type,
                    actor,
                    outcome,
                    details,
                    timestamp,
                )

                prev_ok = stored_prev == expected_prev
                hash_ok = stored_hash == computed_hash

                if not prev_ok or not hash_ok:
                    tampered.append(event_id)
                    logger.warning(
                        "Audit integrity failure at sequence %s",
                        sequence,
                    )
                else:
                    verified += 1

            except (json.JSONDecodeError, TypeError, ValueError):
                tampered.append(event_id)
                logger.warning(
                    "Malformed audit details at sequence %s",
                    sequence,
                )

            # Use the stored hash for subsequent link checking. If this record
            # has changed, the next record's predecessor will be evaluated
            # against the stored value, exposing broken links downstream.
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
                "Chain is valid"
                if chain_valid
                else (
                    f"Chain compromised: {len(tampered)} "
                    "tampered record(s)"
                )
            ),
        }

    # -----------------------------------------------------------------------
    # Checkpoint verification
    # -----------------------------------------------------------------------

    def verify_checkpoints(self) -> Dict[str, Any]:
        """Verify checkpoint signatures and their audit-log anchors."""
        if self._conn is None:
            raise RuntimeError("Audit service not initialized")

        checkpoint_rows = self._conn.execute(
            """
            SELECT sequence, hash, signature, key_id
            FROM audit_checkpoints
            ORDER BY sequence ASC
            """
        ).fetchall()

        event_rows = self._conn.execute(
            """
            SELECT sequence, hash
            FROM audit_events
            ORDER BY sequence ASC
            """
        ).fetchall()

        event_hashes = {
            sequence: chain_hash
            for sequence, chain_hash in event_rows
        }
        max_sequence = max(event_hashes, default=0)

        total = len(checkpoint_rows)
        verified = 0
        failed: List[str] = []

        # Detect duplicate checkpoint sequences.
        checkpoint_counts: Dict[int, int] = {}

        for sequence, _, _, _ in checkpoint_rows:
            checkpoint_counts[sequence] = (
                checkpoint_counts.get(sequence, 0) + 1
            )

        # Detect missing expected periodic checkpoint entries.
        expected_sequences = set(
            range(
                CHECKPOINT_INTERVAL,
                max_sequence + 1,
                CHECKPOINT_INTERVAL,
            )
        )
        present_sequences = set(checkpoint_counts)

        for sequence in sorted(expected_sequences - present_sequences):
            failed.append(
                f"{sequence}: required checkpoint missing"
            )

        # Validate each checkpoint against both the signature and database.
        for sequence, chain_hash, signature_hex, key_id in checkpoint_rows:
            issues: List[str] = []

            if checkpoint_counts[sequence] > 1:
                issues.append("duplicate checkpoint sequence")

            if sequence not in event_hashes:
                issues.append("no matching audit event")
            elif event_hashes[sequence] != chain_hash:
                issues.append(
                    "checkpoint hash does not match audit event"
                )

            if key_id != "ed25519-v1":
                issues.append("unsupported checkpoint key ID")
            elif not self._verify_checkpoint(
                sequence,
                chain_hash,
                signature_hex,
                key_id,
            ):
                issues.append("invalid checkpoint signature")

            if issues:
                failed.append(
                    f"{sequence}: {'; '.join(issues)}"
                )
                logger.warning(
                    "Checkpoint integrity failure at sequence %s: %s",
                    sequence,
                    "; ".join(issues),
                )
            else:
                verified += 1

        all_valid = not failed

        if not all_valid:
            message = (
                f"{len(failed)} checkpoint integrity issue(s) detected"
            )
        elif total == 0:
            message = "No checkpoints required yet"
        else:
            message = "All checkpoints valid"

        return {
            "checkpoints_valid": all_valid,
            "total_checkpoints": total,
            "verified_checkpoints": verified,
            "failed_checkpoints": failed,
            "message": message,
        }

    # -----------------------------------------------------------------------
    # Utility
    # -----------------------------------------------------------------------

    def count(self) -> int:
        """Return the audit event count, or zero if not initialized."""
        if self._conn is None:
            return 0

        return self._conn.execute(
            "SELECT COUNT(*) FROM audit_events"
        ).fetchone()[0]


# Module-level singleton initialized by the application lifespan.
audit_service = AuditService()