"""Pretty output: Rich-style panels for header, payload, signature, expiry."""

from __future__ import annotations

import json
from typing import Any

from .analyzer import TokenAnalysis
from .decoder import DecodedJWT
from .verifier import VerificationResult


# ANSI color codes
class C:
    """ANSI color constants."""

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    UNDERLINE = "\033[4m"

    @classmethod
    def disable(cls) -> None:
        """Disable all colors."""
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = ""
        cls.MAGENTA = cls.CYAN = cls.BOLD = cls.DIM = ""
        cls.RESET = cls.UNDERLINE = ""


def _box(title: str, content: str, color: str = "", width: int = 60) -> str:
    """Draw a simple box around content."""
    reset = C.RESET
    top = f"{color}{'=' * width}{reset}"
    title_line = f"{color}{C.BOLD} {title} {reset}"
    bottom = f"{color}{'-' * width}{reset}"

    lines = [top, title_line, bottom]
    for line in content.splitlines():
        lines.append(f"  {line}")
    lines.append(f"{color}{'=' * width}{reset}")
    return "\n".join(lines)


def format_header(decoded: DecodedJWT) -> str:
    """Format JWT header as a pretty panel."""
    content = json.dumps(decoded.header, indent=2)
    return _box("HEADER", content, C.RED)


def format_payload(decoded: DecodedJWT) -> str:
    """Format JWT payload as a pretty panel."""
    content = json.dumps(decoded.payload, indent=2)
    return _box("PAYLOAD", content, C.BLUE)


def format_signature(decoded: DecodedJWT) -> str:
    """Format JWT signature info."""
    sig_hex = decoded.signature_bytes.hex()
    lines = [
        f"Algorithm: {decoded.algorithm}",
        f"Signature: {sig_hex[:64]}{'...' if len(sig_hex) > 64 else ''}",
        f"Bytes:     {len(decoded.signature_bytes)}",
    ]
    if decoded.key_id:
        lines.append(f"Key ID:    {decoded.key_id}")
    return _box("SIGNATURE", "\n".join(lines), C.YELLOW)


def format_verification(result: VerificationResult) -> str:
    """Format verification result."""
    if result.valid:
        status = f"{C.GREEN}{C.BOLD}VALID{C.RESET}"
    else:
        status = f"{C.RED}{C.BOLD}INVALID{C.RESET}"

    lines = [
        f"Status:    {status}",
        f"Algorithm: {result.algorithm}",
        f"Method:    {result.method}",
    ]
    if result.error:
        lines.append(f"Error:     {C.RED}{result.error}{C.RESET}")
    return _box("VERIFICATION", "\n".join(lines), C.GREEN if result.valid else C.RED)


def format_expiry(analysis: TokenAnalysis) -> str:
    """Format expiry countdown with color coding."""
    lines: list[str] = []

    if analysis.is_expired is None:
        lines.append(f"{C.DIM}No expiry claim (exp) found{C.RESET}")
    elif analysis.is_expired:
        lines.append(f"{C.RED}{C.BOLD}EXPIRED{C.RESET}")
        lines.append(f"Expired: {analysis.expires_at_human}")
        lines.append(f"         {analysis.expires_in_human}")
    else:
        seconds_left = analysis.expires_in_seconds or 0
        if seconds_left < 3600:
            color = C.YELLOW  # < 1 hour
        else:
            color = C.GREEN   # > 1 hour
        lines.append(f"{color}{C.BOLD}ACTIVE{C.RESET}")
        lines.append(f"Expires: {analysis.expires_at_human}")
        lines.append(f"         {analysis.expires_in_human}")

    if analysis.issued_at_human:
        lines.append(f"Issued:  {analysis.issued_at_human}")

    if analysis.not_before_human:
        lines.append(f"Not before: {analysis.not_before_human}")

    return _box("EXPIRY", "\n".join(lines), C.CYAN)


def format_claims(analysis: TokenAnalysis) -> str:
    """Format all claims in a readable way."""
    lines: list[str] = []

    if analysis.issuer:
        lines.append(f"Issuer (iss):   {analysis.issuer}")
    if analysis.subject:
        lines.append(f"Subject (sub):  {analysis.subject}")
    if analysis.audience:
        aud = analysis.audience
        if isinstance(aud, list):
            aud = ", ".join(aud)
        lines.append(f"Audience (aud): {aud}")
    if analysis.jti:
        lines.append(f"Token ID (jti): {analysis.jti}")

    if analysis.custom_claims:
        lines.append("")
        lines.append(f"{C.BOLD}Custom claims:{C.RESET}")
        for k, v in analysis.custom_claims.items():
            val_str = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
            lines.append(f"  {k}: {val_str}")

    if not lines:
        lines.append(f"{C.DIM}No registered claims found{C.RESET}")

    return _box("CLAIMS", "\n".join(lines), C.MAGENTA)


def format_full(decoded: DecodedJWT, analysis: TokenAnalysis, verification: VerificationResult | None = None) -> str:
    """Format a complete JWT inspection output."""
    parts = [
        format_header(decoded),
        "",
        format_payload(decoded),
        "",
        format_signature(decoded),
        "",
        format_expiry(analysis),
        "",
        format_claims(analysis),
    ]
    if verification:
        parts.extend(["", format_verification(verification)])
    return "\n".join(parts)
