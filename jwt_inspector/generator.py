"""Generate JWTs: convenience wrapper around creator with CLI-friendly interface."""

from __future__ import annotations

import json
import secrets
from typing import Any

from .creator import create_jwt


def generate_token(
    payload_json: str | None = None,
    payload_dict: dict[str, Any] | None = None,
    secret: str | None = None,
    key_file: str | None = None,
    algorithm: str = "HS256",
    expiry: int | None = 3600,
    issuer: str | None = None,
    subject: str | None = None,
    audience: str | None = None,
) -> str:
    """Generate a JWT token with convenient defaults.

    Args:
        payload_json: JSON string of payload claims.
        payload_dict: Dict of payload claims (alternative to payload_json).
        secret: Shared secret for HMAC algorithms.
        key_file: Path to PEM private key for RSA/ECDSA.
        algorithm: Signing algorithm.
        expiry: Expiry in seconds from now (default 3600 = 1 hour).
        issuer: Token issuer.
        subject: Token subject.
        audience: Token audience.

    Returns:
        Signed JWT string.
    """
    # Parse payload
    if payload_json:
        try:
            payload = json.loads(payload_json)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON payload: {e}")
    elif payload_dict:
        payload = payload_dict
    else:
        payload = {}

    # Load private key if specified
    private_key = None
    if key_file:
        with open(key_file, "r") as f:
            private_key = f.read()

    # Generate a random secret if needed and not provided
    if algorithm.upper().startswith("HS") and not secret:
        secret = secrets.token_hex(32)

    return create_jwt(
        payload=payload,
        secret=secret,
        private_key_pem=private_key,
        algorithm=algorithm,
        expiry_seconds=expiry,
        issuer=issuer,
        subject=subject,
        audience=audience,
    )


def generate_example_tokens() -> dict[str, str]:
    """Generate example tokens for testing/demo purposes."""
    secret = "demo-secret-key-for-testing"

    tokens = {
        "simple": generate_token(
            payload_dict={"sub": "1234567890", "name": "Jane Doe", "admin": True},
            secret=secret,
            expiry=3600,
        ),
        "expired": create_jwt(
            payload={"sub": "expired-user", "name": "Expired Token"},
            secret=secret,
            algorithm="HS256",
            expiry_seconds=-3600,  # Already expired
        ),
        "no_expiry": create_jwt(
            payload={"sub": "forever", "role": "service"},
            secret=secret,
            algorithm="HS256",
        ),
    }
    return tokens
