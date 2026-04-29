#!/usr/bin/env python3
"""MCP-style stdio server for FindEvil Triage Agent."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from find_evil_agent import inventory, run


TOOLS = [
    {
        "name": "inventory_case",
        "description": "Hash and list files in a read-only DFIR case directory.",
        "inputSchema": {
            "type": "object",
            "properties": {"case_dir": {"type": "string"}},
            "required": ["case_dir"],
        },
    },
    {
        "name": "run_triage",
        "description": "Run read-only triage and self-correction against a case directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_dir": {"type": "string"},
                "out_dir": {"type": "string"},
            },
            "required": ["case_dir"],
        },
    },
]


def handle(request: dict[str, Any]) -> dict[str, Any]:
    request_id = request.get("id")
    method = request.get("method")
    try:
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}}
        if method == "tools/call":
            params = request.get("params", {})
            args = params.get("arguments", {})
            name = params.get("name")
            case_dir = Path(args["case_dir"])
            if name == "inventory_case":
                result = {"files": inventory(case_dir)}
            elif name == "run_triage":
                out_dir = Path(args.get("out_dir", "artifacts"))
                result = run(case_dir, out_dir)
            else:
                raise ValueError(f"Unknown tool: {name}")
            return {"jsonrpc": "2.0", "id": request_id, "result": {"content": [{"type": "json", "json": result}]}}
        raise ValueError(f"Unknown method: {method}")
    except Exception as exc:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": str(exc)}}


def main() -> int:
    for line in sys.stdin:
        if line.strip():
            print(json.dumps(handle(json.loads(line))), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

