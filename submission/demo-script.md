# Demo Script

Target length: under 5 minutes.

1. Show the case directory:

```bash
find data/case-001 -type f -maxdepth 1 -print
```

2. Run the agent:

```bash
python3 src/find_evil_agent.py data/case-001 --out artifacts
```

3. Point out supported findings:

- repeated SSH failures
- failed logins followed by success
- suspicious curl-to-shell command
- unusual outbound port
- cron persistence
- DNS staging signal
- process-to-network correlation

4. Show self-correction:

```bash
grep self_correction artifacts/execution-log.jsonl
```

5. Show the MCP tool surface:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}\n' | python3 src/mcp_server.py
```

6. Open `artifacts/report.json` and show `summary`, `riskScore`, and `selfCorrections`, especially the removed unsupported persistence claim.
7. Close with architecture: detectors produce candidates, correction policy enforces evidence, final report contains only supported claims.
