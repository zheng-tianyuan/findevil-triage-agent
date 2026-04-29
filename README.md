# FindEvil Triage Agent

FindEvil Triage Agent is a read-only incident-response prototype for the FIND EVIL hackathon. It analyzes a small forensic case directory, generates suspicious findings, then performs an explicit self-correction pass that removes or downgrades claims without enough evidence.

The prototype is designed to be portable for demo purposes and shaped for later integration with SANS SIFT / Protocol SIFT through MCP tools.

## Hackathon Fit

- Approach: Custom MCP-ready triage workflow
- Core behavior: autonomous triage with visible self-correction
- Guardrails: read-only dataset access, evidence requirements, hallucination checks, execution logs
- Demo story: investigate a suspicious Linux login and process/network activity case

## Quick Start

```bash
python3 src/find_evil_agent.py data/case-001 --out artifacts
```

Outputs:

- `artifacts/report.json`
- `artifacts/execution-log.jsonl`

## Project Structure

- `src/find_evil_agent.py` - triage and self-correction engine
- `src/mcp_server.py` - MCP-style stdio tool surface for inventory and triage
- `data/case-001/` - synthetic sample case
- `docs/architecture.md` - agent architecture and guardrails
- `docs/dataset.md` - dataset documentation
- `docs/accuracy-report.md` - accuracy report draft
- `submission/devpost-draft.md` - Devpost copy
- `submission/demo-script.md` - 5-minute demo script

## Safety Model

The agent never modifies evidence. Every claim must cite one or more source artifacts. Findings without sufficient support are not hidden; they are recorded in `selfCorrections` so the demo can show the agent correcting itself.

## MCP Demo

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}\n' | python3 src/mcp_server.py
```

Run triage through the tool surface:

```bash
printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_triage","arguments":{"case_dir":"data/case-001","out_dir":"artifacts-mcp"}}}\n' | python3 src/mcp_server.py
```
