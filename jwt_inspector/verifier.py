"""Verify JWT signatures: HS256/384/512, RS256/384/512, ES256/384."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from .decoder import DecodedJWT, _base64url_decode


@dataclass
class VerificationResult:
    """Result of signature verification."""

    valid: bool
    algorithm: str
    method: str  # "hmac", "rsa", "ecdsa", "none"
    error: str | None = None


def verify_hmac(decoded: DecodedJWT, secret: str | bytes) -> VerificationResult:
    """Verify HMAC-SHA signature (HS256, HS384, HS512).

    Args:
        decoded: The decoded JWT.
        secret: The shared secret (string or bytes).

    Returns:
        VerificationResult.
    """
    alg = decoded.algorithm.upper()
    hash_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }

    if alg not in hash_map:
        return VerificationResult(
            valid=False, algorithm=alg, method="hmac",
            error=f"Algorithm {alg} is not HMAC-based",
        )

    if isinstance(secret, str):
        secret = secret.encode("utf-8")

    # The signing input is header_b64.payload_b64
    signing_input = f"{decoded.header_raw}.{decoded.payload_raw}".encode("ascii")

    expected_sig = hmac.new(secret, signing_input, hash_map[alg]).digest()
    actual_sig = decoded.signature_bytes

    is_valid = hmac.compare_digest(expected_sig, actual_sig)

    return VerificationResult(
        valid=is_valid,
        algorithm=alg,
        method="hmac",
        error=None if is_valid else "Signature mismatch",
    )


def verify_rsa(decoded: DecodedJWT, public_key_pem: str | bytes) -> VerificationResult:
    """Verify RSA signature (RS256, RS384, RS512).

    Requires the `cryptography` library.

    Args:
        decoded: The decoded JWT.
        public_key_pem: PEM-encoded RSA public key.

    Returns:
        VerificationResult.
    """
    alg = decoded.algorithm.upper()
    hash_map = {
        "RS256": "SHA256",
        "RS384": "SHA384",
        "RS512": "SHA512",
    }

    if alg not in hash_map:
        return VerificationResult(
            valid=False, algorithm=alg, method="rsa",
            error=f"Algorithm {alg} is not RSA-based",
        )

    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError:
        return VerificationResult(
            valid=False, algorithm=alg, method="rsa",
            error="cryptography library required for RSA verification: pip install cryptography",
        )

    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("utf-8")

    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except Exception as e:
        return VerificationResult(
            valid=False, algorithm=alg, method="rsa",
            error=f"Failed to load public key: {e}",
        )

    hash_cls = {
        "SHA256": hashes.SHA256(),
        "SHA384": hashes.SHA384(),
        "SHA512": hashes.SHA512(),
    }[hash_map[alg]]

    signing_input = f"{decoded.header_raw}.{decoded.payload_raw}".encode("ascii")

    try:
        public_key.verify(  # type: ignore[union-attr]
            decoded.signature_bytes,
            signing_input,
            padding.PKCS1v15(),
            hash_cls,
        )
        return VerificationResult(valid=True, algorithm=alg, method="rsa")
    except Exception as e:
        return VerificationResult(
            valid=False, algorithm=alg, method="rsa",
            error=f"Signature verification failed: {e}",
        )


def verify_ecdsa(decoded: DecodedJWT, public_key_pem: str | bytes) -> VerificationResult:
    """Verify ECDSA signature (ES256, ES384).

    Args:
        decoded: The decoded JWT.
        public_key_pem: PEM-encoded EC public key.

    Returns:
        VerificationResult.
    """
    alg = decoded.algorithm.upper()
    hash_map = {
        "ES256": "SHA256",
        "ES384": "SHA384",
    }

    if alg not in hash_map:
        return VerificationResult(
            valid=False, algorithm=alg, method="ecdsa",
            error=f"Algorithm {alg} is not ECDSA-based",
        )

    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, utils
    except ImportError:
        return VerificationResult(
            valid=False, algorithm=alg, method="ecdsa",
            error="cryptography library required: pip install cryptography",
        )

    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("utf-8")

    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except Exception as e:
        return VerificationResult(
            valid=False, algorithm=alg, method="ecdsa",
            error=f"Failed to load public key: {e}",
        )

    hash_cls = {
        "SHA256": hashes.SHA256(),
        "SHA384": hashes.SHA384(),
    }[hash_map[alg]]

    signing_input = f"{decoded.header_raw}.{decoded.payload_raw}".encode("ascii")

    # JWT ECDSA signatures are r || s (raw), not DER-encoded
    sig = decoded.signature_bytes
    key_size = {"ES256": 32, "ES384": 48}[alg]

    if len(sig) != key_size * 2:
        return VerificationResult(
            valid=False, algorithm=alg, method="ecdsa",
            error=f"Invalid signature length: expected {key_size * 2}, got {len(sig)}",
        )

    r = int.from_bytes(sig[:key_size], byteorder="big")
    s = int.from_bytes(sig[key_size:], byteorder="big")
    der_sig = utils.encode_dss_signature(r, s)

    try:
        public_key.verify(der_sig, signing_input, ec.ECDSA(hash_cls))  # type: ignore[union-attr]
        return VerificationResult(valid=True, algorithm=alg, method="ecdsa")
    except Exception as e:
        return VerificationResult(
            valid=False, algorithm=alg, method="ecdsa",
            error=f"Signature verification failed: {e}",
        )


def verify(decoded: DecodedJWT, secret: str | bytes | None = None, key_pem: str | bytes | None = None) -> VerificationResult:
    """Auto-detect algorithm and verify signature.

    Args:
        decoded: The decoded JWT.
        secret: Shared secret for HMAC algorithms.
        key_pem: PEM public key for RSA/ECDSA algorithms.

    Returns:
        VerificationResult.
    """
    alg = decoded.algorithm.upper()

    if alg == "NONE":
        is_valid = len(decoded.signature_bytes) == 0
        return VerificationResult(
            valid=is_valid, algorithm="none", method="none",
            error=None if is_valid else "Token claims 'none' but has signature",
        )

    if alg.startswith("HS"):
        if secret is None:
            return VerificationResult(
                valid=False, algorithm=alg, method="hmac",
                error="HMAC verification requires --secret",
            )
        return verify_hmac(decoded, secret)

    if alg.startswith("RS"):
        if key_pem is None:
            return VerificationResult(
                valid=False, algorithm=alg, method="rsa",
                error="RSA verification requires --key (PEM public key)",
            )
        return verify_rsa(decoded, key_pem)

    if alg.startswith("ES"):
        if key_pem is None:
            return VerificationResult(
                valid=False, algorithm=alg, method="ecdsa",
                error="ECDSA verification requires --key (PEM public key)",
            )
        return verify_ecdsa(decoded, key_pem)

    return VerificationResult(
        valid=False, algorithm=alg, method="unknown",
        error=f"Unsupported algorithm: {alg}",
    )
