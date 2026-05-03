from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any


def load_json_file(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def load_policy(root: Path) -> dict[str, Any]:
    return load_json_file(root / "security-policy.json", {"profiles": {}, "container_rules": [], "project_rules": []})


def load_ignores(root: Path) -> list[dict[str, Any]]:
    data = load_json_file(root / ".docker-security-ignore.json", {"ignore": []})
    return data.get("ignore", []) if isinstance(data, dict) else []


def profile_config(policy: dict[str, Any], profile: str) -> dict[str, Any]:
    profiles = policy.get("profiles", {})
    if isinstance(profiles, dict):
        return profiles.get(profile, profiles.get("default", {})) or {}
    return {}


def make_policy_finding(rule: dict[str, Any], evidence: str) -> dict[str, str]:
    return {
        "id": str(rule.get("id", "policy_rule")),
        "title": str(rule.get("title", "Policy rule failed")),
        "severity": str(rule.get("severity", "LOW")).upper(),
        "risk": str(rule.get("severity", "LOW")).upper(),
        "category": str(rule.get("category", "policy")),
        "evidence": evidence,
        "impact": str(rule.get("impact", "This configuration does not match the selected security policy.")),
        "recommendation": str(rule.get("recommendation", "Review and harden this setting.")),
        "cis": str(rule.get("cis", "")),
        "source": "policy",
    }


def get_nested(data: dict[str, Any], dotted_path: str, default: Any = None) -> Any:
    current: Any = data
    for key in dotted_path.split("."):
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return current if current is not None else default


def container_policy_findings(container: dict[str, Any], policy: dict[str, Any], profile: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for rule in policy.get("container_rules", []):
        if not isinstance(rule, dict):
            continue
        rule_profiles = rule.get("profiles")
        if rule_profiles and profile not in rule_profiles:
            continue
        rule_type = rule.get("type")
        if rule_type == "host_config_equals":
            path = f"HostConfig.{rule.get('field', '')}"
            actual = get_nested(container, path)
            if actual == rule.get("value"):
                findings.append(make_policy_finding(rule, f"{path}={actual}"))
        elif rule_type == "config_user_in":
            user = str(get_nested(container, "Config.User", "") or "")
            if user in set(rule.get("values", [])):
                findings.append(make_policy_finding(rule, f"Config.User={user or '<empty>'}"))
        elif rule_type == "env_name_contains":
            patterns = [str(item).upper() for item in rule.get("patterns", [])]
            for env_var in get_nested(container, "Config.Env", []) or []:
                key = str(env_var).split("=", 1)[0]
                if any(pattern in key.upper() for pattern in patterns):
                    findings.append(make_policy_finding(rule, f"{key}=***"))
        elif rule_type == "mount_contains":
            token = str(rule.get("token", ""))
            mount_text = json.dumps(container.get("Mounts") or [], default=str)
            bind_text = json.dumps(get_nested(container, "HostConfig.Binds", []) or [], default=str)
            if token and token in f"{mount_text} {bind_text}":
                findings.append(make_policy_finding(rule, f"mount contains {token}"))
        elif rule_type == "image_matches":
            image = str(get_nested(container, "Config.Image", ""))
            token = str(rule.get("contains", ""))
            if token and token.lower() in image.lower():
                findings.append(make_policy_finding(rule, f"Config.Image={image}"))
    return findings


def project_policy_findings(root: Path, policy: dict[str, Any], profile: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for rule in policy.get("project_rules", []):
        if not isinstance(rule, dict):
            continue
        rule_profiles = rule.get("profiles")
        if rule_profiles and profile not in rule_profiles:
            continue
        path = root / str(rule.get("path", ""))
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if rule.get("type") == "file_contains":
            token = str(rule.get("token", ""))
            if token and token in text:
                findings.append(make_policy_finding(rule, f"{path} contains {token}"))
        elif rule.get("type") == "file_missing":
            token = str(rule.get("token", ""))
            if token and token not in text:
                findings.append(make_policy_finding(rule, f"{path} missing {token}"))
    return findings


def is_ignore_expired(ignore: dict[str, Any]) -> bool:
    expires = ignore.get("expires")
    if not expires:
        return False
    try:
        return date.fromisoformat(str(expires)) < date.today()
    except ValueError:
        return False


def ignore_matches(ignore: dict[str, Any], finding: dict[str, Any], target: dict[str, Any]) -> bool:
    if is_ignore_expired(ignore):
        return False
    for key, target_key in (("id", "id"), ("category", "category"), ("severity", "severity")):
        expected = ignore.get(key)
        if expected and str(finding.get(target_key, "")).upper() != str(expected).upper():
            return False
    image = ignore.get("image_contains")
    if image and image.lower() not in str(target.get("image", "")).lower():
        return False
    container = ignore.get("container")
    if container and not str(target.get("id", "")).startswith(str(container)):
        return False
    return True


def apply_ignores(
    findings: list[dict[str, Any]],
    ignores: list[dict[str, Any]],
    target: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    active: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    for finding in findings:
        matched = next((ignore for ignore in ignores if ignore_matches(ignore, finding, target)), None)
        if matched:
            finding = dict(finding)
            finding["ignored_reason"] = matched.get("reason", "")
            suppressed.append(finding)
        else:
            active.append(finding)
    return active, suppressed
