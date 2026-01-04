import json
import hashlib
import time
import uuid
from pathlib import Path
from datetime import datetime

# Paths
BASE_DIR = Path(__file__).resolve().parent
POLICY_PATH = BASE_DIR / "audit_policy.json"
LOG_PATH = BASE_DIR / "audit_log.jsonl"

# Load audit policy
with open(POLICY_PATH, "r") as f:
    AUDIT_POLICY = json.load(f)

HASH_ALGO = hashlib.sha256


def _hash(data: str) -> str:
    return HASH_ALGO(data.encode("utf-8")).hexdigest()


def _get_last_log_hash() -> str:
    """
    Returns the hash of the last log entry.
    If no logs exist, return a genesis hash.
    """
    if not LOG_PATH.exists():
        return _hash("GENESIS")

    with open(LOG_PATH, "r") as f:
        last_line = None
        for line in f:
            last_line = line

    if last_line:
        return json.loads(last_line)["current_log_hash"]

    return _hash("GENESIS")


def log_event(
    *,
    user_role: str,
    detected_risk: str,
    matched_patterns: list,
    action_taken: str,
    routing_decision: str,
    request_hash: str,
    processing_latency_ms: int | None = None
):
    """
    Writes a single audit log entry.
    Privacy-safe, append-only, hash-chained.
    """

    previous_hash = _get_last_log_hash()

    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.utcnow().isoformat() + "Z",
        "user_role": user_role,
        "detected_risk_level": detected_risk,
        "matched_pattern_ids": matched_patterns,
        "policy_action": action_taken,
        "routing_decision": routing_decision,
        "request_hash": request_hash,
        "previous_log_hash": previous_hash
    }

    if processing_latency_ms is not None:
        event["processing_latency_ms"] = processing_latency_ms

    # Create current hash (hash of event + previous hash)
    event_serialized = json.dumps(event, sort_keys=True)
    current_hash = _hash(previous_hash + event_serialized)

    event["current_log_hash"] = current_hash

    # Append-only write
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")


