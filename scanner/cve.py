from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any


def trivy_command() -> str | None:
    configured = os.environ.get("TRIVY_PATH")
    if configured:
        return configured
    return shutil.which("trivy")


def grype_command() -> str | None:
    configured = os.environ.get("GRYPE_PATH")
    if configured:
        return configured
    return shutil.which("grype")


def scanner_status() -> dict[str, str]:
    trivy = trivy_command()
    if trivy:
        return {"tool": "trivy", "status": "available", "command": trivy}
    grype = grype_command()
    if grype:
        return {"tool": "grype", "status": "available", "command": grype}
    return {"tool": "none", "status": "not_installed"}


def severity_from_cvss(score: float | None, fallback: str) -> str:
    if score is None:
        return fallback.upper()
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def trivy_findings(image: str) -> list[dict[str, str]]:
    command = trivy_command() or "trivy"
    result = subprocess.run(
        [command, "image", "--quiet", "--format", "json", image],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode not in (0, 1) or not result.stdout.strip():
        return []
    data = json.loads(result.stdout)
    findings: list[dict[str, str]] = []
    for item in data.get("Results", []):
        for vuln in item.get("Vulnerabilities", []) or []:
            severity = str(vuln.get("Severity", "LOW")).upper()
            cve = str(vuln.get("VulnerabilityID", "CVE"))
            package = str(vuln.get("PkgName", "unknown"))
            installed = str(vuln.get("InstalledVersion", "unknown"))
            fixed = str(vuln.get("FixedVersion", "not fixed"))
            findings.append({
                "id": f"cve_{cve.lower()}_{package}",
                "title": f"{cve} affects {package}",
                "severity": severity,
                "risk": severity,
                "category": "cve",
                "evidence": f"{package} {installed}, fixed: {fixed}",
                "impact": str(vuln.get("Title") or vuln.get("Description") or "Known package vulnerability detected."),
                "recommendation": f"Upgrade {package} to {fixed} or rebuild the image from a patched base.",
                "cve": cve,
                "package": package,
                "installed_version": installed,
                "fixed_version": fixed,
                "source": "trivy",
                "cis": "CIS Docker 4.6",
            })
    return findings


def grype_findings(image: str) -> list[dict[str, str]]:
    command = grype_command() or "grype"
    result = subprocess.run(
        [command, image, "-o", "json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode not in (0, 1) or not result.stdout.strip():
        return []
    data = json.loads(result.stdout)
    findings: list[dict[str, str]] = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        cve = str(vuln.get("id", "CVE"))
        package = str(artifact.get("name", "unknown"))
        installed = str(artifact.get("version", "unknown"))
        fixed_versions = vuln.get("fix", {}).get("versions", []) or []
        fixed = ", ".join(fixed_versions) if fixed_versions else "not fixed"
        severity = str(vuln.get("severity", "LOW")).upper()
        findings.append({
            "id": f"cve_{cve.lower()}_{package}",
            "title": f"{cve} affects {package}",
            "severity": severity,
            "risk": severity,
            "category": "cve",
            "evidence": f"{package} {installed}, fixed: {fixed}",
            "impact": str(vuln.get("description") or "Known package vulnerability detected."),
            "recommendation": f"Upgrade {package} to {fixed} or rebuild the image from a patched base.",
            "cve": cve,
            "package": package,
            "installed_version": installed,
            "fixed_version": fixed,
            "source": "grype",
            "cis": "CIS Docker 4.6",
        })
    return findings


def scan_image(image: str, enabled: bool = True) -> tuple[list[dict[str, str]], dict[str, Any]]:
    status = scanner_status()
    status["enabled"] = str(enabled)
    if not enabled or status["tool"] == "none":
        return [], status
    try:
        if status["tool"] == "trivy":
            findings = trivy_findings(image)
        else:
            findings = grype_findings(image)
        status["status"] = "completed"
        status["findings"] = str(len(findings))
        return findings, status
    except (json.JSONDecodeError, OSError, subprocess.SubprocessError) as exc:
        status["status"] = "failed"
        status["error"] = str(exc)
        return [], status
