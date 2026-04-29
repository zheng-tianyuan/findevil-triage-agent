# FindEvil Triage Agent

## Inspiration

Incident response agents are only useful if they can show their work and correct themselves. FIND EVIL’s focus on autonomous DFIR made me want to build a triage agent that treats evidence integrity and self-correction as core behavior rather than a prompt add-on.

## What It Does

FindEvil Triage Agent analyzes a read-only forensic case directory, inventories and hashes artifacts, detects suspicious login, process, network, cron, file-timeline, and DNS activity, creates candidate findings, and then runs a self-correction pass. Unsupported claims are removed or downgraded and recorded in the execution log.

## How I Built It

The prototype is a Python CLI plus MCP-style stdio tool surface designed for later SIFT / Protocol SIFT workflows. It uses separate detector functions for auth logs, process snapshots, network snapshots, cron artifacts, file timelines, and DNS logs. A correlation stage links process and network evidence before policy-based correction.

## Self-Correction

The demo intentionally injects an unsupported “malware persistence” claim. The agent removes it because no cited artifact supports it. It also downgrades a high-severity scheduled-task finding when only one direct artifact supports the claim. This makes both removal and severity correction visible in the live terminal demo.

## Accuracy and Evidence

Every final finding cites source artifacts and selectors. Every case file is SHA-256 hashed before analysis. The output includes a final JSON report, risk scores, tactic tags, summary metrics, self-corrections, and a JSONL execution log.

## What's Next

Next steps include exposing detectors as MCP tools, running against SIFT timeline artifacts, adding memory and filesystem timeline analyzers, and expanding benchmark cases.
