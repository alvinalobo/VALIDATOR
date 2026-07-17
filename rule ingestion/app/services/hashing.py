"""
hashing.py

Single responsibility: compute a deterministic content hash for a rule file.
This hash is used for change detection (skip re-parsing unchanged rules)
and as a stable identifier when a rule has no declared `id` field.
"""

import hashlib


def compute_sha256(content: str) -> str:
    """
    Compute the SHA-256 hex digest of rule file content.

    We hash the raw text (not the parsed structure) so that any change
    to the file — including comments/whitespace that might carry meaning
    in KQL — is reflected in the hash.
    """
    normalized = content.encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()
