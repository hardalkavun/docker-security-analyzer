from __future__ import annotations

from typing import Any

SEVERITY_RANK = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def all_active_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for container in report.get("containers", []):
        findings.extend(f for f in container.get("findings", []) if isinstance(f, dict))
    project = report.get("project_files", {})
    findings.extend(f for f in project.get("findings", []) if isinstance(f, dict))
    return findings


def evaluate_gate(report: dict[str, Any], fail_on: str = "CRITICAL") -> dict[str, Any]:
    threshold = SEVERITY_RANK.get(fail_on.upper(), SEVERITY_RANK["CRITICAL"])
    blocking = [
        finding for finding in all_active_findings(report)
        if SEVERITY_RANK.get(str(finding.get("severity", "LOW")).upper(), 0) >= threshold
    ]
    return {
        "fail_on": fail_on.upper(),
        "passed": len(blocking) == 0,
        "blocking_findings": len(blocking),
        "blocking_ids": [finding.get("id") for finding in blocking[:20]],
    }
