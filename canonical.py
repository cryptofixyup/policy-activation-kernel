"""
Deterministic canonical serialization and hashing for the policy-activation.v1 kernel.

This module provides:
- canonical_serialize(value) -> str
- canonical_hash(value) -> str

It uses a stable JSON representation (sorted keys, fixed separators)
to ensure reproducible hashes across environments.
"""

import json
import hashlib
from typing import Any


def canonical_serialize(value: Any) -> str:
    """
    Produce a deterministic JSON string representation of `value`.

    This is a simplified RFC-8785-style canonicalization:
    - keys are sorted
    - separators are fixed
    - no whitespace beyond what is required
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def canonical_hash(value: Any) -> str:
    """
    Compute a SHA-256 hash over the canonical serialization of `value`.

    Returns the hex digest string.
    """
    serialized = canonical_serialize(value)
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return digest
