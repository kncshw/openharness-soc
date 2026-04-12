#!/usr/bin/env python3
"""Pretty-printer for `oh -p ... --output-format stream-json` output.

Reads JSON-line events from stdin and prints a human-readable trace:
  - Tool calls with truncated args
  - Tool results with first line preview and ✓ / ✗ status
  - Final assistant text
  - Stream errors and system messages

Usage:
    oh -p "your prompt" \
       --api-format openai --base-url ... --api-key ... --model ... \
       --system-prompt "$(cat docs/soc-analyst-prompt-min.md)" \
       --permission-mode full_auto \
       --output-format stream-json 2>&1 | ~/bin/oh-pretty.py

Anything that doesn't parse as JSON is printed as-is, so plain Python tracebacks
or stderr noise from the underlying tool still come through.
"""

from __future__ import annotations

import json
import sys


# Limits chosen so a typical SOC investigation prints ~1 line per tool call
# and ~1 line per tool result, even when the underlying payloads are huge.
ARG_VALUE_TRUNCATE = 60
RESULT_PREVIEW_TRUNCATE = 160


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "..."


def _format_args(tool_input: object) -> str:
    if not isinstance(tool_input, dict):
        return str(tool_input)
    parts = []
    for key, val in tool_input.items():
        sval = val if isinstance(val, str) else json.dumps(val, ensure_ascii=False)
        parts.append(f"{key}={_truncate(sval, ARG_VALUE_TRUNCATE)}")
    return " ".join(parts)


def _first_meaningful_line(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return text.strip()


def main() -> int:
    for raw in sys.stdin:
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            # Not JSON — pass through (probably stderr from a tool or python warning)
            print(line, flush=True)
            continue

        etype = ev.get("type", "")

        if etype == "tool_started":
            args = _format_args(ev.get("tool_input"))
            print(f"  ▸ {ev.get('tool_name', '?')}({args})", flush=True)

        elif etype == "tool_completed":
            output = (ev.get("output") or "").strip()
            preview = _truncate(_first_meaningful_line(output), RESULT_PREVIEW_TRUNCATE) if output else "(no output)"
            marker = "✗" if ev.get("is_error") else "✓"
            print(f"  {marker} {ev.get('tool_name', '?')} → {preview}", flush=True)

        elif etype == "assistant_complete":
            text = (ev.get("text") or "").strip()
            if text:
                print(file=sys.stdout, flush=True)
                print("=== ASSISTANT ===", flush=True)
                print(text, flush=True)
                print(file=sys.stdout, flush=True)

        elif etype == "system":
            msg = ev.get("message", "")
            if msg:
                print(f"  [system] {msg}", flush=True)

        elif etype == "assistant_delta":
            # Skip — would create a flood of partial-text fragments. The full
            # text comes through 'assistant_complete' at the end of each turn.
            continue

        else:
            # Unknown event types: print compact JSON so nothing is hidden
            print(f"  [{etype}] {json.dumps(ev, ensure_ascii=False)[:240]}", flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
