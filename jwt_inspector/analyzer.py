"""Analyze token: check expiry, issued-at, not-before, audience, issuer."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .decoder import DecodedJWT


@dataclass
class TokenAnalysis:
    """Analysis of JWT claims."""

    algorithm: str
    is_expired: bool | None  # None if no exp claim
    expires_at: float | None
    expires_in_seconds: float | None
    issued_at: float | None
    not_before: float | None
    issuer: str | None
    subject: str | None
    audience: str | list[str] | None
    jti: str | None
    custom_claims: dict[str, Any]

    @property
    def expires_in_human(self) -> str | None:
        """Human-readable time until/since expiry."""
        if self.expires_in_seconds is None:
            return None
        secs = self.expires_in_seconds
        if secs <= 0:
            return _format_duration(abs(secs)) + " ago (EXPIRED)"
        return "in " + _format_duration(secs)

    @property
    def issued_at_human(self) -> str | None:
        if self.issued_at is None:
            return None
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.issued_at))

    @property
    def expires_at_human(self) -> str | None:
        if self.expires_at is None:
            return None
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.expires_at))

    @property
    def not_before_human(self) -> str | None:
        if self.not_before is None:
            return None
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.not_before))


REGISTERED_CLAIMS = {"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}


def _format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    secs = int(abs(seconds))
    if secs < 60:
        return f"{secs}s"
    elif secs < 3600:
        m, s = divmod(secs, 60)
        return f"{m}m {s}s"
    elif secs < 86400:
        h, remainder = divmod(secs, 3600)
        m, s = divmod(remainder, 60)
        return f"{h}h {m}m {s}s"
    else:
        d, remainder = divmod(secs, 86400)
        h, remainder = divmod(remainder, 3600)
        m, _ = divmod(remainder, 60)
        return f"{d}d {h}h {m}m"


def analyze(decoded: DecodedJWT) -> TokenAnalysis:
    """Analyze a decoded JWT's claims."""
    payload = decoded.payload
    now = time.time()

    exp = payload.get("exp")
    is_expired = None
    expires_in = None
    if exp is not None:
        try:
            exp_float = float(exp)
            is_expired = now > exp_float
            expires_in = exp_float - now
        except (TypeError, ValueError):
            exp = None

    iat = payload.get("iat")
    if iat is not None:
        try:
            iat = float(iat)
        except (TypeError, ValueError):
            iat = None

    nbf = payload.get("nbf")
    if nbf is not None:
        try:
            nbf = float(nbf)
        except (TypeError, ValueError):
            nbf = None

    custom = {k: v for k, v in payload.items() if k not in REGISTERED_CLAIMS}

    return TokenAnalysis(
        algorithm=decoded.algorithm,
        is_expired=is_expired,
        expires_at=float(exp) if exp is not None else None,
        expires_in_seconds=expires_in,
        issued_at=iat,
        not_before=nbf,
        issuer=payload.get("iss"),
        subject=payload.get("sub"),
        audience=payload.get("aud"),
        jti=payload.get("jti"),
        custom_claims=custom,
    )


def format_analysis(analysis: TokenAnalysis, color: bool = True) -> str:
    """Format analysis for terminal display."""
    if color:
        RED = "\033[91m"
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        BOLD = "\033[1m"
        RESET = "\033[0m"
        DIM = "\033[2m"
    else:
        RED = GREEN = YELLOW = BOLD = RESET = DIM = ""

    lines: list[str] = []
    lines.append(f"{BOLD}=== Token Analysis ==={RESET}")
    lines.append(f"  Algorithm: {analysis.algorithm}")

    if analysis.is_expired is not None:
        if analysis.is_expired:
            lines.append(f"  Status:    {RED}EXPIRED{RESET}")
        else:
            lines.append(f"  Status:    {GREEN}VALID{RESET}")

    if analysis.expires_at_human:
        lines.append(f"  Expires:   {analysis.expires_at_human} ({analysis.expires_in_human})")

    if analysis.issued_at_human:
        lines.append(f"  Issued:    {analysis.issued_at_human}")

    if analysis.not_before_human:
        lines.append(f"  Not before:{analysis.not_before_human}")

    if analysis.issuer:
        lines.append(f"  Issuer:    {analysis.issuer}")

    if analysis.subject:
        lines.append(f"  Subject:   {analysis.subject}")

    if analysis.audience:
        aud = analysis.audience
        if isinstance(aud, list):
            aud = ", ".join(aud)
        lines.append(f"  Audience:  {aud}")

    if analysis.jti:
        lines.append(f"  Token ID:  {analysis.jti}")

    if analysis.custom_claims:
        lines.append(f"\n{BOLD}  Custom claims:{RESET}")
        for k, v in analysis.custom_claims.items():
            lines.append(f"    {DIM}{k}{RESET}: {v}")

    return "\n".join(lines)
