"""
Blockchain-style Chain of Custody — immutable evidence log.
Each entry's hash is included in the next, creating a chain.
Any tampering invalidates all subsequent entries.
"""

import hashlib
import json
from datetime import datetime, timezone


class ChainOfCustody:
    """
    Cryptographic chain of custody for forensic evidence.
    Each action creates an immutable log entry linked to the previous.
    This is technical evidence integrity proof.
    """

    def __init__(self, case_id: str, apk_sha256: str, apk_size: int):
        self.case_id = case_id
        self.chain = []
        self._add_entry("EVIDENCE_RECEIVED", {
            "sha256": apk_sha256,
            "size_bytes": apk_size,
            "received": datetime.now(timezone.utc).isoformat()
        })

    def _add_entry(self, action: str, data: dict):
        """Add a new entry to the chain."""
        entry = {
            "seq": len(self.chain),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "data": data,
            "prev_hash": (
                hashlib.sha256(json.dumps(self.chain[-1], sort_keys=True).encode()).hexdigest()
                if self.chain else "GENESIS"
            )
        }
        # Sign this entry with its own hash
        entry_for_hash = {k: v for k, v in entry.items()}
        entry["entry_hash"] = hashlib.sha256(
            json.dumps(entry_for_hash, sort_keys=True).encode()
        ).hexdigest()
        self.chain.append(entry)

    def log(self, action: str, **kwargs):
        """Log an action to the chain."""
        self._add_entry(action, kwargs)

    def verify_integrity(self) -> bool:
        """Verify no entry has been modified — returns False if tampered."""
        for i, entry in enumerate(self.chain):
            stored_hash = entry.get("entry_hash")
            entry_without_hash = {k: v for k, v in entry.items() if k != "entry_hash"}
            computed_hash = hashlib.sha256(
                json.dumps(entry_without_hash, sort_keys=True).encode()
            ).hexdigest()
            if stored_hash != computed_hash:
                return False
            if i > 0:
                prev_hash = hashlib.sha256(
                    json.dumps(self.chain[i - 1], sort_keys=True).encode()
                ).hexdigest()
                if entry.get("prev_hash") != prev_hash:
                    return False
        return True

    def export(self) -> dict:
        """Export the chain for report inclusion."""
        return {
            "case_id": self.case_id,
            "entry_count": len(self.chain),
            "integrity": "VERIFIED" if self.verify_integrity() else "COMPROMISED",
            "chain": self.chain
        }
