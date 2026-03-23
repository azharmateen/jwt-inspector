"""Create JWTs: from JSON payload + secret/key, configurable algorithm and expiry."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from .decoder import _base64url_encode


def create_jwt(
    payload: dict[str, Any],
    secret: str | bytes | None = None,
    private_key_pem: str | bytes | None = None,
    algorithm: str = "HS256",
    expiry_seconds: int | None = None,
    issuer: str | None = None,
    subject: str | None = None,
    audience: str | None = None,
    jti: str | None = None,
    extra_headers: dict[str, Any] | None = None,
) -> str:
    """Create and sign a JWT.

    Args:
        payload: The JWT payload claims.
        secret: Shared secret for HMAC algorithms.
        private_key_pem: PEM private key for RSA/ECDSA.
        algorithm: Signing algorithm (HS256, HS384, HS512, RS256, etc.).
        expiry_seconds: If set, add exp claim N seconds from now.
        issuer: If set, add iss claim.
        subject: If set, add sub claim.
        audience: If set, add aud claim.
        jti: If set, add jti claim.
        extra_headers: Additional header claims.

    Returns:
        The signed JWT string.
    """
    now = time.time()

    # Build header
    header: dict[str, Any] = {"alg": algorithm, "typ": "JWT"}
    if extra_headers:
        header.update(extra_headers)

    # Build payload with registered claims
    full_payload = dict(payload)
    if "iat" not in full_payload:
        full_payload["iat"] = int(now)
    if expiry_seconds is not None and "exp" not in full_payload:
        full_payload["exp"] = int(now) + expiry_seconds
    if issuer and "iss" not in full_payload:
        full_payload["iss"] = issuer
    if subject and "sub" not in full_payload:
        full_payload["sub"] = subject
    if audience and "aud" not in full_payload:
        full_payload["aud"] = audience
    if jti and "jti" not in full_payload:
        full_payload["jti"] = jti

    # Encode header and payload
    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _base64url_encode(json.dumps(full_payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}"

    # Sign
    alg = algorithm.upper()

    if alg == "NONE":
        return f"{signing_input}."

    if alg.startswith("HS"):
        if secret is None:
            raise ValueError("HMAC algorithms require a secret")
        sig = _sign_hmac(signing_input, secret, alg)
    elif alg.startswith("RS"):
        if private_key_pem is None:
            raise ValueError("RSA algorithms require a private key")
        sig = _sign_rsa(signing_input, private_key_pem, alg)
    elif alg.startswith("ES"):
        if private_key_pem is None:
            raise ValueError("ECDSA algorithms require a private key")
        sig = _sign_ecdsa(signing_input, private_key_pem, alg)
    else:
        raise ValueError(f"Unsupported algorithm: {alg}")

    sig_b64 = _base64url_encode(sig)
    return f"{signing_input}.{sig_b64}"


def _sign_hmac(signing_input: str, secret: str | bytes, alg: str) -> bytes:
    """Sign with HMAC."""
    if isinstance(secret, str):
        secret = secret.encode("utf-8")

    hash_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    if alg not in hash_map:
        raise ValueError(f"Unknown HMAC algorithm: {alg}")

    return hmac.new(secret, signing_input.encode("ascii"), hash_map[alg]).digest()


def _sign_rsa(signing_input: str, private_key_pem: str | bytes, alg: str) -> bytes:
    """Sign with RSA."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode("utf-8")

    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    hash_map = {
        "RS256": hashes.SHA256(),
        "RS384": hashes.SHA384(),
        "RS512": hashes.SHA512(),
    }

    return private_key.sign(  # type: ignore[union-attr]
        signing_input.encode("ascii"),
        padding.PKCS1v15(),
        hash_map[alg],
    )


def _sign_ecdsa(signing_input: str, private_key_pem: str | bytes, alg: str) -> bytes:
    """Sign with ECDSA, returning raw r||s format."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode("utf-8")

    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    hash_map = {
        "ES256": hashes.SHA256(),
        "ES384": hashes.SHA384(),
    }

    der_sig = private_key.sign(  # type: ignore[union-attr]
        signing_input.encode("ascii"),
        ec.ECDSA(hash_map[alg]),
    )

    # Convert DER to raw r||s
    r, s = utils.decode_dss_signature(der_sig)
    key_size = {"ES256": 32, "ES384": 48}[alg]
    return r.to_bytes(key_size, byteorder="big") + s.to_bytes(key_size, byteorder="big")
