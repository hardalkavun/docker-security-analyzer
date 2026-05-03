from __future__ import annotations

import csv
import io
import json
from typing import Any


def all_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for container in report.get("containers", []):
        for finding in container.get("findings", []):
            row = dict(finding)
            row["target_type"] = "container"
            row["target"] = container.get("id", "")
            row["image"] = container.get("image", "")
            findings.append(row)
    project = report.get("project_files", {})
    for finding in project.get("findings", []):
        row = dict(finding)
        row["target_type"] = "project"
        row["target"] = "repository"
        row["image"] = ""
        findings.append(row)
    return findings


def to_csv(report: dict[str, Any]) -> str:
    output = io.StringIO()
    fields = [
        "target_type",
        "target",
        "image",
        "id",
        "title",
        "severity",
        "category",
        "evidence",
        "impact",
        "recommendation",
        "cis",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(all_findings(report))
    return output.getvalue()


def to_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Docker Security Report",
        "",
        f"Scan timestamp: `{report.get('scan_timestamp', 'unknown')}`",
        "",
        "## Summary",
        "",
    ]
    containers = report.get("containers", [])
    summary = {level: sum(1 for c in containers if c.get("risk") == level) for level in ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL")}
    for level, count in summary.items():
        lines.append(f"- {level}: {count}")
    lines.extend(["", "## Container Findings", ""])
    for container in containers:
        lines.append(f"### {container.get('id', '')[:12]} / {container.get('image', 'unknown')}")
        lines.append(f"Risk: **{container.get('risk')}** / Score: `{container.get('score')}`")
        if container.get("recommended_run"):
            lines.extend(["", "Recommended run:", "", "```bash", container["recommended_run"], "```"])
        for finding in container.get("findings", []):
            lines.extend([
                "",
                f"- **{finding.get('severity')}** `{finding.get('id')}`: {finding.get('title')}",
                f"  Evidence: `{finding.get('evidence', '')}`",
                f"  Fix: {finding.get('recommendation', '')}",
            ])
        lines.append("")
    project = report.get("project_files", {})
    lines.extend(["## Project Findings", ""])
    for finding in project.get("findings", []):
        lines.extend([
            f"- **{finding.get('severity')}** `{finding.get('id')}`: {finding.get('title')}",
            f"  Evidence: `{finding.get('evidence', '')}`",
            f"  Fix: {finding.get('recommendation', '')}",
        ])
    return "\n".join(lines).strip() + "\n"


def sarif_level(severity: str) -> str:
    severity = severity.upper()
    if severity in {"CRITICAL", "HIGH"}:
        return "error"
    if severity == "MEDIUM":
        return "warning"
    return "note"


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    findings = all_findings(report)
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = str(finding.get("id", "finding"))
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": finding.get("title", rule_id),
            "shortDescription": {"text": finding.get("title", rule_id)},
            "fullDescription": {"text": finding.get("impact", "")},
            "help": {"text": finding.get("recommendation", "")},
            "properties": {
                "category": finding.get("category", ""),
                "severity": finding.get("severity", ""),
                "cis": finding.get("cis", ""),
            },
        })
        evidence = str(finding.get("evidence", ""))
        artifact = "Docker runtime"
        if ":" in evidence and ("Dockerfile" in evidence or ".yml" in evidence or ".yaml" in evidence):
            artifact = evidence.split(":", 1)[0]
        results.append({
            "ruleId": rule_id,
            "level": sarif_level(str(finding.get("severity", "LOW"))),
            "message": {"text": f"{finding.get('title')}: {evidence}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact.replace("\\", "/")},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {
                "target": finding.get("target", ""),
                "image": finding.get("image", ""),
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "docker-security-analyzer",
                    "informationUri": "https://github.com/",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def to_json_text(data: Any) -> str:
    return json.dumps(data, indent=2)
