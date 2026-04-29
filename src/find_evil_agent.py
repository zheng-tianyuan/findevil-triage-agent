#!/usr/bin/env python3
"""FindEvil Triage Agent: read-only synthetic DFIR triage with self-correction."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class Evidence:
    artifact: str
    selector: str
    excerpt: str

    def as_dict(self) -> dict[str, str]:
        return {"artifact": self.artifact, "selector": self.selector, "excerpt": self.excerpt}


@dataclass
class Finding:
    title: str
    severity: str
    claim: str
    evidence: list[Evidence] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    confidence: float = 0.5
    status: str = "candidate"

    def as_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "claim": self.claim,
            "status": self.status,
            "riskScore": risk_score(self),
            "confidence": self.confidence,
            "tactics": self.tactics,
            "evidence": [item.as_dict() for item in self.evidence],
        }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def log_event(log_path: Path, event: str, payload: dict[str, Any]) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "payload": payload,
    }
    with log_path.open("a") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def read_lines(case_dir: Path, name: str) -> list[str]:
    path = case_dir / name
    if not path.exists():
        return []
    return path.read_text(errors="replace").splitlines()


def read_json(case_dir: Path, name: str) -> Any:
    path = case_dir / name
    if not path.exists():
        return []
    return json.loads(path.read_text())


def read_csv_rows(case_dir: Path, name: str) -> list[dict[str, str]]:
    lines = read_lines(case_dir, name)
    if not lines:
        return []
    headers = [header.strip() for header in lines[0].split(",")]
    rows = []
    for line in lines[1:]:
        values = [value.strip() for value in line.split(",")]
        rows.append(dict(zip(headers, values, strict=False)))
    return rows


def inventory(case_dir: Path) -> list[dict[str, str]]:
    items = []
    for path in sorted(case_dir.iterdir()):
        if path.is_file():
            items.append({"file": path.name, "sha256": sha256(path)})
    return items


def risk_score(finding: Finding) -> int:
    severity_points = {"low": 20, "medium": 45, "high": 70, "critical": 90}
    evidence_points = min(len(finding.evidence) * 6, 18)
    confidence_points = round(finding.confidence * 12)
    return min(100, severity_points.get(finding.severity, 35) + evidence_points + confidence_points)


def detect_auth_anomalies(case_dir: Path) -> list[Finding]:
    lines = read_lines(case_dir, "auth.log")
    findings: list[Finding] = []
    failed_by_ip: dict[str, list[tuple[int, str]]] = {}
    accepted_by_ip: dict[str, list[tuple[int, str]]] = {}

    for idx, line in enumerate(lines, start=1):
        parts = line.split()
        ip = parts[-1] if parts else "unknown"
        if "Failed password" in line:
            failed_by_ip.setdefault(ip, []).append((idx, line))
        if "Accepted password" in line:
            accepted_by_ip.setdefault(ip, []).append((idx, line))

    for ip, failed in failed_by_ip.items():
        if len(failed) >= 3:
            evidence = [Evidence("auth.log", f"line {line_no}", line) for line_no, line in failed[:5]]
            findings.append(Finding(
                title="Repeated SSH failures",
                severity="medium",
                claim=f"{ip} generated {len(failed)} failed SSH login attempts.",
                evidence=evidence,
                tactics=["initial-access"],
                confidence=0.78,
            ))
    for ip, accepted in accepted_by_ip.items():
        if ip in failed_by_ip:
            evidence = [Evidence("auth.log", f"line {line_no}", line) for line_no, line in failed_by_ip[ip][:2]]
            evidence.extend(Evidence("auth.log", f"line {line_no}", line) for line_no, line in accepted[:2])
            findings.append(Finding(
                title="Failed logins followed by success",
                severity="high",
                claim=f"{ip} had failed SSH attempts followed by a successful login.",
                evidence=evidence,
                tactics=["initial-access", "valid-accounts"],
                confidence=0.86,
            ))

    return findings


def detect_process_anomalies(case_dir: Path) -> list[Finding]:
    processes = read_json(case_dir, "processes.json")
    findings: list[Finding] = []
    suspicious_terms = ("curl ", "wget ", "base64", "nc ", "bash -c")

    for index, process in enumerate(processes):
        command = process.get("cmdline", "")
        if any(term in command for term in suspicious_terms):
            findings.append(Finding(
                title="Suspicious command line",
                severity="medium",
                claim=f"Process {process.get('pid')} ran a command often seen in hands-on-keyboard activity.",
                evidence=[Evidence("processes.json", f"record {index}", json.dumps(process, sort_keys=True))],
                tactics=["execution"],
                confidence=0.74,
            ))

    return findings


def detect_network_anomalies(case_dir: Path) -> list[Finding]:
    connections = read_json(case_dir, "network.json")
    findings: list[Finding] = []
    for index, connection in enumerate(connections):
        if connection.get("remote_port") in {4444, 8081, 9001}:
            findings.append(Finding(
                title="Unusual outbound port",
                severity="medium",
                claim=f"Outbound connection to {connection.get('remote_ip')}:{connection.get('remote_port')} needs review.",
                evidence=[Evidence("network.json", f"record {index}", json.dumps(connection, sort_keys=True))],
                tactics=["command-and-control"],
                confidence=0.68,
            ))
    return findings


def detect_persistence(case_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    cron_lines = read_lines(case_dir, "crontab.txt")
    timeline = read_csv_rows(case_dir, "file_timeline.csv")

    for idx, line in enumerate(cron_lines, start=1):
        if "curl" in line or "bash" in line or "/tmp/" in line:
            findings.append(Finding(
                title="Suspicious scheduled task",
                severity="high",
                claim="A scheduled task runs shell/network activity from a temporary location.",
                evidence=[Evidence("crontab.txt", f"line {idx}", line)],
                tactics=["persistence", "execution"],
                confidence=0.82,
            ))

    for index, row in enumerate(timeline):
        path = row.get("path", "")
        action = row.get("action", "")
        if path.startswith("/etc/cron") and action in {"created", "modified"}:
            findings.append(Finding(
                title="Cron artifact changed",
                severity="medium",
                claim=f"Cron-related artifact changed at {row.get('timestamp')}: {path}.",
                evidence=[Evidence("file_timeline.csv", f"row {index + 2}", json.dumps(row, sort_keys=True))],
                tactics=["persistence"],
                confidence=0.71,
            ))
    return findings


def detect_dns_anomalies(case_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    lines = read_lines(case_dir, "dns.log")
    evidence_by_domain: dict[str, list[Evidence]] = {}
    for idx, line in enumerate(lines, start=1):
        if not ("pastebin" in line or "raw.githubusercontent" in line or ".top" in line):
            continue
        parts = line.split()
        domain = parts[2] if len(parts) > 2 else "unknown-domain"
        evidence_by_domain.setdefault(domain, []).append(Evidence("dns.log", f"line {idx}", line))
    for domain, evidence in evidence_by_domain.items():
        findings.append(Finding(
            title="Suspicious DNS lookup",
            severity="medium",
            claim=f"Host resolved {domain}, a domain pattern often used for payload staging or disposable infrastructure.",
            evidence=evidence,
            tactics=["command-and-control"],
            confidence=0.68 if len(evidence) > 1 else 0.63,
        ))
    return findings


def detect_cross_artifact_correlation(case_dir: Path) -> list[Finding]:
    processes = read_json(case_dir, "processes.json")
    connections = read_json(case_dir, "network.json")
    findings: list[Finding] = []
    process_by_pid = {process.get("pid"): (index, process) for index, process in enumerate(processes)}

    for index, connection in enumerate(connections):
        pid = connection.get("pid")
        process_record = process_by_pid.get(pid)
        if not process_record:
            continue
        process_index, process = process_record
        command = process.get("cmdline", "")
        if ("curl" in command or "wget" in command) and connection.get("remote_port") in {8081, 9001, 4444}:
            findings.append(Finding(
                title="Process-to-network correlation",
                severity="high",
                claim=f"PID {pid} both launched suspicious download behavior and connected to an unusual remote port.",
                evidence=[
                    Evidence("processes.json", f"record {process_index}", json.dumps(process, sort_keys=True)),
                    Evidence("network.json", f"record {index}", json.dumps(connection, sort_keys=True)),
                ],
                tactics=["execution", "command-and-control"],
                confidence=0.9,
            ))
    return findings


def inject_uncertain_candidate() -> Finding:
    return Finding(
        title="Possible malware persistence",
        severity="high",
        claim="The host may have malware persistence configured.",
        evidence=[],
        tactics=["persistence"],
        confidence=0.4,
    )


def self_correct(findings: list[Finding]) -> tuple[list[Finding], list[dict[str, Any]]]:
    corrected: list[Finding] = []
    corrections: list[dict[str, Any]] = []
    for finding in findings:
        if not finding.evidence:
            corrections.append({
                "title": finding.title,
                "action": "removed",
                "reason": "No cited artifact supported the claim.",
                "originalClaim": finding.claim,
            })
            continue
        if finding.severity == "high" and len(finding.evidence) < 2:
            corrections.append({
                "title": finding.title,
                "action": "downgraded",
                "reason": "High severity requires at least two evidence references in this demo policy.",
                "originalSeverity": finding.severity,
                "newSeverity": "medium",
            })
            finding.severity = "medium"
            finding.confidence = min(finding.confidence, 0.69)
        finding.status = "supported"
        corrected.append(finding)
    corrected.sort(key=risk_score, reverse=True)
    return corrected, corrections


def summarize_findings(findings: list[Finding], corrections: list[dict[str, Any]]) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    tactics: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        for tactic in finding.tactics:
            tactics[tactic] = tactics.get(tactic, 0) + 1
    return {
        "supportedFindingCount": len(findings),
        "selfCorrectionCount": len(corrections),
        "bySeverity": by_severity,
        "byTactic": tactics,
        "topRiskScore": max([risk_score(finding) for finding in findings], default=0),
    }


def run(case_dir: Path, out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "execution-log.jsonl"
    if log_path.exists():
        log_path.unlink()

    files = inventory(case_dir)
    log_event(log_path, "inventory", {"files": files})

    candidates: list[Finding] = []
    for detector_name, detector in [
        ("auth", detect_auth_anomalies),
        ("process", detect_process_anomalies),
        ("network", detect_network_anomalies),
        ("persistence", detect_persistence),
        ("dns", detect_dns_anomalies),
        ("correlation", detect_cross_artifact_correlation),
    ]:
        detected = detector(case_dir)
        candidates.extend(detected)
        log_event(log_path, "detector_result", {"detector": detector_name, "count": len(detected)})

    candidates.append(inject_uncertain_candidate())
    log_event(log_path, "candidate_findings", {"count": len(candidates), "findings": [item.as_dict() for item in candidates]})

    supported, corrections = self_correct(candidates)
    log_event(log_path, "self_correction", {"corrections": corrections})

    report = {
        "agent": "FindEvil Triage Agent",
        "case": case_dir.name,
        "artifactInventory": files,
        "summary": summarize_findings(supported, corrections),
        "supportedFindings": [finding.as_dict() for finding in supported],
        "selfCorrections": corrections,
        "accuracyControls": {
            "falsePositiveControl": "Unsupported claims are removed or downgraded before final report.",
            "evidenceIntegrity": "All source files are hashed before analysis.",
            "hallucinationControl": "Final claims require cited artifacts.",
        },
    }
    (out_dir / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True))
    log_event(log_path, "report_written", {"path": str(out_dir / "report.json")})
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Run read-only DFIR triage with self-correction.")
    parser.add_argument("case_dir", type=Path)
    parser.add_argument("--out", type=Path, default=Path("artifacts"))
    args = parser.parse_args()

    report = run(args.case_dir, args.out)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
