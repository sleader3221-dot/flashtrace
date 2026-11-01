# flashtrace

Forensic triage for ESP32-family SPI flash dumps. See `CLAUDE.md` for the design.

## Development

```bash
python -m pip install -e ".[dev]"
ruff check src tests && ruff format --check src tests
mypy
pytest
```

`FLASHTRACE_REQUIRE_TOOLS=1` (set in CI) turns a missing `esptool` / `hypothesis`
into a test failure instead of a skip.
