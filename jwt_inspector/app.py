"""Optional Textual TUI for JWT inspection."""

from __future__ import annotations

import json

try:
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.widgets import Footer, Header, Input, Static, TextArea

    HAS_TEXTUAL = True
except ImportError:
    HAS_TEXTUAL = False


def check_textual() -> bool:
    """Check if textual is available."""
    return HAS_TEXTUAL


if HAS_TEXTUAL:
    from .analyzer import analyze, format_analysis
    from .decoder import decode, format_decoded, JWTDecodeError

    class JWTInspectorApp(App):
        """A Textual TUI for JWT inspection."""

        TITLE = "JWT Inspector"
        CSS = """
        #token-input {
            dock: top;
            height: 3;
            margin: 1;
        }
        #header-panel {
            width: 1fr;
            height: 100%;
            border: solid green;
            padding: 1;
        }
        #payload-panel {
            width: 2fr;
            height: 100%;
            border: solid blue;
            padding: 1;
        }
        #analysis-panel {
            width: 1fr;
            height: 100%;
            border: solid yellow;
            padding: 1;
        }
        #main-panels {
            height: 1fr;
        }
        """

        def compose(self) -> ComposeResult:
            yield Header()
            yield Input(placeholder="Paste JWT token here...", id="token-input")
            with Horizontal(id="main-panels"):
                yield Static("Header\n\nPaste a token above", id="header-panel")
                yield Static("Payload\n\nPaste a token above", id="payload-panel")
                yield Static("Analysis\n\nPaste a token above", id="analysis-panel")
            yield Footer()

        def on_input_submitted(self, event: Input.Submitted) -> None:
            """Handle token input."""
            token = event.value.strip()
            if not token:
                return

            try:
                decoded = decode(token)
                analysis = analyze(decoded)

                header_text = "HEADER\n\n" + json.dumps(decoded.header, indent=2)
                payload_text = "PAYLOAD\n\n" + json.dumps(decoded.payload, indent=2)
                analysis_text = format_analysis(analysis, color=False)

                self.query_one("#header-panel", Static).update(header_text)
                self.query_one("#payload-panel", Static).update(payload_text)
                self.query_one("#analysis-panel", Static).update(analysis_text)

            except JWTDecodeError as e:
                self.query_one("#header-panel", Static).update(f"Error: {e}")
                self.query_one("#payload-panel", Static).update("")
                self.query_one("#analysis-panel", Static).update("")

    def run_tui() -> None:
        """Launch the TUI."""
        app = JWTInspectorApp()
        app.run()

else:
    def run_tui() -> None:
        """Stub when textual is not installed."""
        print("TUI requires the 'textual' library.")
        print("Install with: pip install jwt-inspector[tui]")
