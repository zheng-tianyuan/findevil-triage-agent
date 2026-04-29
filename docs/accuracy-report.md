# Accuracy Report

## False Positives

The demo intentionally injects one unsupported candidate finding: “Possible malware persistence.” The self-correction pass removes it because it has no cited artifact.

## Missed Artifacts

This prototype currently reviews `auth.log`, `processes.json`, `network.json`, `crontab.txt`, `file_timeline.csv`, and `dns.log`. It does not yet analyze full disk images, memory captures, browser artifacts, or packet captures.

## Hallucinated Claims

Final claims require evidence references. Claims without evidence are logged in `selfCorrections` and excluded from `supportedFindings`.

## Evidence Integrity

All files in the case directory are hashed with SHA-256 before analysis and included in the final report.

## Current Ground-Truth Result

Expected supported findings: 8.

Expected self-corrections: 2.

- One high-severity scheduled-task finding is downgraded because it has only one direct artifact.
- One unsupported persistence claim is removed.
