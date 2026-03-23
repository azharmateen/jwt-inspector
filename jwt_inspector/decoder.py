"""Decode JWT: split header.payload.signature, base64url decode, parse JSON."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any


class JWTDecodeError(Exception):
    """Raised when a JWT cannot be decoded."""


@dataclass
class DecodedJWT:
    """A fully decoded JWT."""

    raw: str
    header: dict[str, Any]
    payload: dict[str, Any]
    signature_bytes: bytes
    header_raw: str
    payload_raw: str
    signature_raw: str

    @property
    def algorithm(self) -> str:
        return self.header.get("alg", "none")

    @property
    def token_type(self) -> str:
        return self.header.get("typ", "JWT")

    @property
    def key_id(self) -> str | None:
        return self.header.get("kid")


def _base64url_decode(data: str) -> bytes:
    """Decode base64url-encoded data with padding fix."""
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode(token: str) -> DecodedJWT:
    """Decode a JWT token into its components.

    Args:
        token: The JWT string (header.payload.signature).

    Returns:
        DecodedJWT with parsed header, payload, and raw signature.

    Raises:
        JWTDecodeError: If the token is malformed.
    """
    token = token.strip()

    parts = token.split(".")
    if len(parts) != 3:
        raise JWTDecodeError(
            f"Invalid JWT: expected 3 dot-separated parts, got {len(parts)}"
        )

    header_b64, payload_b64, sig_b64 = parts

    # Decode header
    try:
        header_bytes = _base64url_decode(header_b64)
        header = json.loads(header_bytes)
    except (json.JSONDecodeError, Exception) as e:
        raise JWTDecodeError(f"Invalid JWT header: {e}")

    # Decode payload
    try:
        payload_bytes = _base64url_decode(payload_b64)
        payload = json.loads(payload_bytes)
    except (json.JSONDecodeError, Exception) as e:
        raise JWTDecodeError(f"Invalid JWT payload: {e}")

    # Decode signature (raw bytes, may not be valid UTF-8)
    try:
        sig_bytes = _base64url_decode(sig_b64) if sig_b64 else b""
    except Exception:
        sig_bytes = b""

    return DecodedJWT(
        raw=token,
        header=header,
        payload=payload,
        signature_bytes=sig_bytes,
        header_raw=header_b64,
        payload_raw=payload_b64,
        signature_raw=sig_b64,
    )


def format_decoded(decoded: DecodedJWT, color: bool = True) -> str:
    """Format a decoded JWT for terminal display."""
    lines: list[str] = []

    # Colors (ANSI)
    if color:
        RED = "\033[91m"
        GREEN = "\033[92m"
        BLUE = "\033[94m"
        YELLOW = "\033[93m"
        BOLD = "\033[1m"
        RESET = "\033[0m"
        DIM = "\033[2m"
    else:
        RED = GREEN = BLUE = YELLOW = BOLD = RESET = DIM = ""

    lines.append(f"{BOLD}=== JWT Header ==={RESET}")
    lines.append(f"{RED}{json.dumps(decoded.header, indent=2)}{RESET}")
    lines.append("")

    lines.append(f"{BOLD}=== JWT Payload ==={RESET}")
    lines.append(f"{BLUE}{json.dumps(decoded.payload, indent=2)}{RESET}")
    lines.append("")

    lines.append(f"{BOLD}=== Signature ==={RESET}")
    lines.append(f"{DIM}Algorithm: {decoded.algorithm}{RESET}")
    sig_hex = decoded.signature_bytes.hex()
    if len(sig_hex) > 64:
        sig_hex = sig_hex[:64] + "..."
    lines.append(f"{YELLOW}{sig_hex}{RESET}")

    if decoded.key_id:
        lines.append(f"{DIM}Key ID (kid): {decoded.key_id}{RESET}")

    return "\n".join(lines)
