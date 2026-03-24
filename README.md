# jwt-inspector

[![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-blue?logo=anthropic&logoColor=white)](https://claude.ai/code)


Offline JWT decoder, verifier, and editor. Never paste tokens into random websites again.

## Installation

```bash
pip install jwt-inspector

# With TUI support
pip install jwt-inspector[tui]
```

## Usage

```bash
# Decode a JWT (shows header, payload, signature)
jwt-inspector decode eyJhbGciOiJIUzI1NiIs...

# Check expiry status
jwt-inspector expiry eyJhbGciOiJIUzI1NiIs...

# Verify signature with HMAC secret
jwt-inspector verify eyJhbGciOiJIUzI1NiIs... --secret "my-secret"

# Verify with RSA public key
jwt-inspector verify eyJhbGciOiJSUzI1NiIs... --key pubkey.pem

# Create a new JWT
jwt-inspector create --payload '{"sub":"123","name":"John"}' --secret "my-secret"
jwt-inspector create --payload '{"sub":"123"}' --secret "my-secret" --exp 3600 --alg HS256

# Launch TUI (requires textual)
jwt-inspector tui
```

## Features

- Decode JWT header, payload, and signature without any external service
- Verify HS256/HS384/HS512 with shared secret
- Verify RS256/RS384/RS512 with PEM public key
- Verify ES256/ES384 with EC public key
- Human-readable expiry countdown
- Create and sign new JWTs
- Colorized terminal output
- Optional Textual TUI for interactive inspection

## Supported Algorithms

| Algorithm | Type | Key Required |
|-----------|------|-------------|
| HS256, HS384, HS512 | HMAC | Shared secret |
| RS256, RS384, RS512 | RSA | Public key (PEM) |
| ES256, ES384 | ECDSA | EC public key (PEM) |
| none | Unsigned | N/A |

## License

MIT
