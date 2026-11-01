"""``python -m flashtrace``: typer CLI when available, argparse fallback otherwise."""

from __future__ import annotations

import sys


def main() -> int:
    try:
        from flashtrace.cli import app  # noqa: PLC0415
    except ImportError:
        from flashtrace.commands import fallback_main  # noqa: PLC0415

        return fallback_main(sys.argv[1:])
    app()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
