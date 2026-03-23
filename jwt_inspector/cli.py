"""CLI for jwt-inspector: decode, verify, create, expiry, tui."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .analyzer import analyze, format_analysis
from .creator import create_jwt
from .decoder import JWTDecodeError, decode, format_decoded
from .verifier import verify


@click.group()
@click.version_option(package_name="jwt-inspector")
def cli() -> None:
    """jwt-inspector: Offline JWT decoder, verifier, and editor."""


@cli.command()
@click.argument("token")
@click.option("--no-color", is_flag=True, help="Disable color output.")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON.")
def decode_cmd(token: str, no_color: bool, json_out: bool) -> None:
    """Decode a JWT and display header, payload, signature."""
    try:
        decoded = decode(token)
    except JWTDecodeError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    if json_out:
        output = {
            "header": decoded.header,
            "payload": decoded.payload,
            "signature_hex": decoded.signature_bytes.hex(),
        }
        click.echo(json.dumps(output, indent=2))
    else:
        click.echo(format_decoded(decoded, color=not no_color))
        click.echo("")
        analysis = analyze(decoded)
        click.echo(format_analysis(analysis, color=not no_color))


# Register as "decode" command name
decode_cmd.name = "decode"


@cli.command()
@click.argument("token")
@click.option("--secret", "-s", default=None, help="HMAC shared secret.")
@click.option("--key", "-k", "key_file", default=None, type=click.Path(exists=True), help="Path to PEM public key.")
@click.option("--no-color", is_flag=True, help="Disable color output.")
def verify_cmd(token: str, secret: str | None, key_file: str | None, no_color: bool) -> None:
    """Verify a JWT signature."""
    try:
        decoded = decode(token)
    except JWTDecodeError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    key_pem = None
    if key_file:
        key_pem = Path(key_file).read_bytes()

    result = verify(decoded, secret=secret, key_pem=key_pem)

    if no_color:
        GREEN = RED = BOLD = RESET = ""
    else:
        GREEN = "\033[92m"
        RED = "\033[91m"
        BOLD = "\033[1m"
        RESET = "\033[0m"

    if result.valid:
        click.echo(f"{GREEN}{BOLD}VALID{RESET} - Signature verified ({result.algorithm}, {result.method})")
    else:
        click.echo(f"{RED}{BOLD}INVALID{RESET} - {result.error}")
        sys.exit(1)


verify_cmd.name = "verify"


@cli.command()
@click.argument("token")
@click.option("--no-color", is_flag=True, help="Disable color output.")
def expiry(token: str, no_color: bool) -> None:
    """Check JWT expiry status."""
    try:
        decoded = decode(token)
    except JWTDecodeError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    analysis = analyze(decoded)

    if no_color:
        GREEN = RED = YELLOW = BOLD = RESET = ""
    else:
        GREEN = "\033[92m"
        RED = "\033[91m"
        YELLOW = "\033[93m"
        BOLD = "\033[1m"
        RESET = "\033[0m"

    if analysis.is_expired is None:
        click.echo(f"{YELLOW}No expiry claim (exp) found in token{RESET}")
        return

    if analysis.is_expired:
        click.echo(f"{RED}{BOLD}EXPIRED{RESET}")
        click.echo(f"  Expired at: {analysis.expires_at_human}")
        click.echo(f"  {analysis.expires_in_human}")
    else:
        click.echo(f"{GREEN}{BOLD}NOT EXPIRED{RESET}")
        click.echo(f"  Expires at: {analysis.expires_at_human}")
        click.echo(f"  {analysis.expires_in_human}")

    if analysis.issued_at_human:
        click.echo(f"  Issued at:  {analysis.issued_at_human}")


@cli.command()
@click.option("--payload", "-p", required=True, help='JSON payload (e.g., \'{"sub":"123"}\').')
@click.option("--secret", "-s", default=None, help="HMAC secret for signing.")
@click.option("--key", "-k", "key_file", default=None, type=click.Path(exists=True), help="PEM private key for RSA/ECDSA.")
@click.option("--alg", default="HS256", help="Algorithm (HS256, RS256, ES256, etc.).")
@click.option("--exp", "expiry_seconds", default=None, type=int, help="Expiry in seconds from now.")
@click.option("--iss", "issuer", default=None, help="Issuer claim.")
@click.option("--sub", "subject", default=None, help="Subject claim.")
@click.option("--aud", "audience", default=None, help="Audience claim.")
def create(payload: str, secret: str | None, key_file: str | None, alg: str,
           expiry_seconds: int | None, issuer: str | None, subject: str | None,
           audience: str | None) -> None:
    """Create a new signed JWT."""
    try:
        payload_dict = json.loads(payload)
    except json.JSONDecodeError as e:
        click.echo(f"Invalid JSON payload: {e}", err=True)
        sys.exit(1)

    private_key = None
    if key_file:
        private_key = Path(key_file).read_bytes()

    try:
        token = create_jwt(
            payload=payload_dict,
            secret=secret,
            private_key_pem=private_key,
            algorithm=alg,
            expiry_seconds=expiry_seconds,
            issuer=issuer,
            subject=subject,
            audience=audience,
        )
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    click.echo(token)


@cli.command("tui")
def tui_cmd() -> None:
    """Launch the interactive TUI (requires textual)."""
    from .app import check_textual, run_tui

    if not check_textual():
        click.echo("TUI requires 'textual'. Install with: pip install jwt-inspector[tui]")
        sys.exit(1)

    run_tui()


if __name__ == "__main__":
    cli()
