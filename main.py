from __future__ import annotations

import json
import re
import subprocess
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner import cve
from scanner import exporters
from scanner import gate
from scanner import policy as policy_engine

RISK_LEVELS = ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_POINTS = {
    "LOW": 5,
    "MEDIUM": 12,
    "HIGH": 25,
    "CRITICAL": 50,
}
CATEGORY_ORDER = ("runtime", "mounts", "network", "secrets", "image", "cve", "dockerfile", "compose", "policy")
SENSITIVE_ENV_PATTERNS = (
    "PASSWORD",
    "PASSWD",
    "TOKEN",
    "SECRET",
    "API_KEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
    "DATABASE_URL",
    "CONNECTION_STRING",
)
SENSITIVE_MOUNT_PATHS = (
    "/var/run/docker.sock",
    "/etc",
    "/root",
    "/var/lib/docker",
    "/proc",
    "/sys",
    "/dev",
)
SENSITIVE_PORTS = {
    "22": "SSH",
    "2375": "Docker daemon without TLS",
    "2376": "Docker daemon",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "6379": "Redis",
    "9200": "Elasticsearch",
    "27017": "MongoDB",
}
COMMON_SERVICE_IMAGES = ("nginx", "redis", "postgres", "mysql", "mongo", "elasticsearch")
TOOL_IMAGES = ("kali", "parrot", "security")
DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "DAC_READ_SEARCH",
    "SYS_MODULE",
    "SYS_RAWIO",
}


def run_docker(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False)


def get_containers(*, include_stopped: bool = False) -> list[str]:
    args = ["ps", "--format", "{{.ID}}"]
    if include_stopped:
        args.insert(1, "--all")
    result = run_docker(args)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "docker ps failed")
    return [cid for cid in result.stdout.strip().splitlines() if cid]


def inspect_container(cid: str) -> dict[str, Any]:
    result = run_docker(["inspect", cid])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"docker inspect failed for {cid}")
    inspected = json.loads(result.stdout)
    if not inspected:
        raise RuntimeError(f"docker inspect returned no data for {cid}")
    return inspected[0]


def make_finding(
    finding_id: str,
    title: str,
    severity: str,
    category: str,
    evidence: str,
    impact: str,
    recommendation: str,
    cis: str | None = None,
) -> dict[str, str]:
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "risk": severity,
        "category": category,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation,
        "cis": cis or "",
    }


def get_nested(data: dict[str, Any], path: tuple[str, ...], default: Any = None) -> Any:
    current: Any = data
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return current if current is not None else default


def normalize_image_tag(image: str) -> tuple[str, str]:
    if "@" in image:
        return image, "digest"
    last_segment = image.rsplit("/", 1)[-1]
    if ":" not in last_segment:
        return image, "latest"
    return image.rsplit(":", 1)


def is_tool_image(image: str) -> bool:
    return any(token in image.lower() for token in TOOL_IMAGES)


def published_port_findings(ports: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    exposed_count = 0

    for container_port, bindings in ports.items():
        if not bindings:
            continue
        exposed_count += 1
        port_number = container_port.split("/", 1)[0]
        for binding in bindings:
            host_ip = binding.get("HostIp", "")
            host_port = binding.get("HostPort", port_number)
            public_bind = host_ip in ("", "0.0.0.0", "::")
            if public_bind and port_number in SENSITIVE_PORTS:
                findings.append(make_finding(
                    "sensitive_port_public",
                    f"{SENSITIVE_PORTS[port_number]} port is publicly exposed",
                    "HIGH",
                    "network",
                    f"{host_ip or '0.0.0.0'}:{host_port}->{container_port}",
                    "A sensitive service can be reached from outside the host network.",
                    "Bind the port to 127.0.0.1, put it behind a firewall, or remove the published port.",
                    "CIS Docker 5.7",
                ))
            elif public_bind:
                findings.append(make_finding(
                    "port_public",
                    "Container port is bound on all interfaces",
                    "MEDIUM",
                    "network",
                    f"{host_ip or '0.0.0.0'}:{host_port}->{container_port}",
                    "The service is reachable from external networks if host firewall rules allow it.",
                    "Bind only to required interfaces, for example 127.0.0.1, or restrict ingress with firewall rules.",
                    "CIS Docker 5.7",
                ))

    if exposed_count > 5:
        findings.append(make_finding(
            "many_exposed_ports",
            "Container exposes many ports",
            "MEDIUM",
            "network",
            f"{exposed_count} published ports detected",
            "A large exposed surface increases the chance of accidental service exposure.",
            "Publish only the ports required for the application workflow.",
            "CIS Docker 5.7",
        ))

    return findings


def mount_findings(container: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    mounts = container.get("Mounts") or []
    binds = get_nested(container, ("HostConfig", "Binds"), []) or []
    mount_text = json.dumps(mounts, default=str) + " " + json.dumps(binds, default=str)

    if "/var/run/docker.sock" in mount_text:
        findings.append(make_finding(
            "docker_socket_mount",
            "Docker socket is mounted into the container",
            "CRITICAL",
            "mounts",
            "/var/run/docker.sock detected in mounts",
            "The container can control the Docker daemon and may gain host-level control.",
            "Remove the docker.sock mount or place a restricted Docker socket proxy in front of it.",
            "CIS Docker 5.31",
        ))

    for mount in mounts:
        source = str(mount.get("Source", ""))
        destination = str(mount.get("Destination", ""))
        read_write = bool(mount.get("RW"))
        combined = f"{source}:{destination}"
        for sensitive_path in SENSITIVE_MOUNT_PATHS:
            if sensitive_path in combined and sensitive_path != "/var/run/docker.sock":
                findings.append(make_finding(
                    "sensitive_host_path_mount",
                    "Sensitive host path is mounted",
                    "HIGH" if read_write else "MEDIUM",
                    "mounts",
                    f"{source} -> {destination} ({'rw' if read_write else 'ro'})",
                    "Sensitive host files or kernel interfaces may be exposed inside the container.",
                    "Remove the mount, narrow it to the exact required path, and use read-only mode where possible.",
                    "CIS Docker 5.10",
                ))
                break
        if read_write and mount.get("Type") == "bind":
            findings.append(make_finding(
                "writable_bind_mount",
                "Writable host bind mount detected",
                "MEDIUM",
                "mounts",
                f"{source} -> {destination} (rw)",
                "A compromised container can modify host files available through the bind mount.",
                "Use read-only bind mounts with :ro unless the application explicitly needs write access.",
                "CIS Docker 5.10",
            ))

    return findings


def secret_findings(env_vars: list[str]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for env_var in env_vars:
        key = env_var.split("=", 1)[0]
        if any(pattern in key.upper() for pattern in SENSITIVE_ENV_PATTERNS):
            findings.append(make_finding(
                "secret_in_environment",
                "Potential secret stored in environment variable",
                "HIGH",
                "secrets",
                f"{key}=***",
                "Environment variables are commonly exposed through inspect output, logs, crash dumps, or process metadata.",
                "Move secrets to Docker secrets, an external secret manager, or short-lived runtime credentials.",
                "CIS Docker 5.30",
            ))
    return findings


def runtime_findings(container: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    config = container.get("Config") or {}
    host_config = container.get("HostConfig") or {}
    user = config.get("User") or ""
    security_opts = host_config.get("SecurityOpt") or []
    cap_add = host_config.get("CapAdd") or []
    cap_drop = host_config.get("CapDrop") or []
    security_opt_values = [str(opt).lower() for opt in security_opts]

    if user in ("", "root", "0"):
        findings.append(make_finding(
            "container_runs_as_root",
            "Container runs as root",
            "MEDIUM",
            "runtime",
            f"Config.User={user or '<empty>'}",
            "A process escape or application bug has a larger blast radius when the process runs as root.",
            "Set a non-root USER in the Dockerfile or run the container with --user.",
            "CIS Docker 4.1",
        ))

    if host_config.get("Privileged"):
        findings.append(make_finding(
            "privileged_container",
            "Container runs in privileged mode",
            "CRITICAL",
            "runtime",
            "HostConfig.Privileged=true",
            "Privileged containers receive broad host capabilities and device access.",
            "Remove --privileged and grant only the exact capabilities or devices required.",
            "CIS Docker 5.4",
        ))

    if not host_config.get("ReadonlyRootfs"):
        findings.append(make_finding(
            "writable_root_filesystem",
            "Root filesystem is writable",
            "LOW",
            "runtime",
            "HostConfig.ReadonlyRootfs=false",
            "Malware or compromised processes can persist files inside the container filesystem.",
            "Run with --read-only and mount explicit writable tmpfs or volumes for required paths.",
            "CIS Docker 5.12",
        ))

    if "ALL" not in [str(item).upper() for item in cap_drop]:
        findings.append(make_finding(
            "capabilities_not_dropped",
            "Linux capabilities are not dropped by default",
            "LOW",
            "runtime",
            f"HostConfig.CapDrop={cap_drop or 'not set'}",
            "The container may retain capabilities that are not needed by the application.",
            "Start with --cap-drop ALL and add back only required capabilities.",
            "CIS Docker 5.3",
        ))

    if cap_add:
        dangerous_caps = sorted(str(cap).upper() for cap in cap_add if str(cap).upper() in DANGEROUS_CAPABILITIES)
        severity = "HIGH" if dangerous_caps else "MEDIUM"
        findings.append(make_finding(
            "extra_capabilities_added",
            "Extra Linux capabilities are added",
            severity,
            "runtime",
            f"HostConfig.CapAdd={cap_add}",
            "Additional capabilities can enable privilege escalation or network manipulation.",
            "Remove added capabilities unless each one is required and documented.",
            "CIS Docker 5.3",
        ))

    if not any("no-new-privileges:true" in opt for opt in security_opt_values):
        findings.append(make_finding(
            "no_new_privileges_missing",
            "no-new-privileges is not enabled",
            "LOW",
            "runtime",
            f"HostConfig.SecurityOpt={security_opts or 'not set'}",
            "Processes may be able to gain additional privileges through setuid or file capabilities.",
            "Run with --security-opt no-new-privileges:true.",
            "CIS Docker 5.25",
        ))

    if any("seccomp=unconfined" in opt or "seccomp:unconfined" in opt for opt in security_opt_values):
        findings.append(make_finding(
            "seccomp_unconfined",
            "Seccomp is explicitly disabled",
            "HIGH",
            "runtime",
            f"HostConfig.SecurityOpt={security_opts}",
            "The container can access a much larger syscall surface than Docker's default profile allows.",
            "Remove seccomp=unconfined and use Docker's default or a workload-specific restricted seccomp profile.",
            "CIS Docker 5.21",
        ))
    elif not any(opt.startswith("seccomp=") or opt.startswith("seccomp:") for opt in security_opt_values):
        findings.append(make_finding(
            "seccomp_profile_not_explicit",
            "No explicit seccomp profile is configured",
            "LOW",
            "runtime",
            f"HostConfig.SecurityOpt={security_opts or 'not set'}",
            "The default may be acceptable, but sensitive workloads should pin an expected seccomp profile.",
            "Use Docker's default seccomp profile explicitly or a workload-specific restricted profile.",
            "CIS Docker 5.21",
        ))

    if any("apparmor=unconfined" in opt or "apparmor:unconfined" in opt for opt in security_opt_values):
        findings.append(make_finding(
            "apparmor_unconfined",
            "AppArmor is explicitly disabled",
            "HIGH",
            "runtime",
            f"HostConfig.SecurityOpt={security_opts}",
            "The container loses an additional mandatory access-control boundary on supported hosts.",
            "Remove apparmor=unconfined and use Docker's default AppArmor profile or a tailored profile.",
            "CIS Docker 5.20",
        ))

    if host_config.get("PidMode") == "host":
        findings.append(make_finding(
            "host_pid_namespace",
            "Container shares the host PID namespace",
            "HIGH",
            "runtime",
            "HostConfig.PidMode=host",
            "The container can inspect or interact with host processes.",
            "Avoid --pid=host unless this is a tightly controlled monitoring workload.",
            "CIS Docker 5.15",
        ))

    if host_config.get("IpcMode") == "host":
        findings.append(make_finding(
            "host_ipc_namespace",
            "Container shares the host IPC namespace",
            "HIGH",
            "runtime",
            "HostConfig.IpcMode=host",
            "The container may access host IPC resources and shared memory.",
            "Avoid --ipc=host unless explicitly required.",
            "CIS Docker 5.16",
        ))

    if host_config.get("UsernsMode") == "host":
        findings.append(make_finding(
            "host_user_namespace",
            "Container disables user namespace isolation",
            "MEDIUM",
            "runtime",
            "HostConfig.UsernsMode=host",
            "The container does not benefit from user namespace remapping on hosts where it is configured.",
            "Avoid --userns=host unless there is a documented compatibility reason.",
            "CIS Docker 5.28",
        ))

    devices = host_config.get("Devices") or []
    if devices:
        findings.append(make_finding(
            "host_device_mapped",
            "Host device is mapped into the container",
            "HIGH",
            "runtime",
            f"HostConfig.Devices={devices}",
            "Direct device access can weaken host isolation or expose sensitive host resources.",
            "Remove device mappings or narrow them to the exact device and permissions required.",
            "CIS Docker 5.17",
        ))

    healthcheck = config.get("Healthcheck") or {}
    if healthcheck.get("Test") == ["NONE"]:
        findings.append(make_finding(
            "healthcheck_disabled",
            "Image healthcheck is explicitly disabled",
            "LOW",
            "runtime",
            "Config.Healthcheck.Test=['NONE']",
            "Disabled healthchecks make unhealthy services harder to detect and respond to.",
            "Keep a lightweight HEALTHCHECK for long-running services where possible.",
            "CIS Docker 4.6",
        ))

    return findings


def network_findings(container: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    host_config = container.get("HostConfig") or {}
    network_mode = str(host_config.get("NetworkMode") or "")
    ports = get_nested(container, ("NetworkSettings", "Ports"), {}) or {}

    if network_mode == "host":
        findings.append(make_finding(
            "host_network_mode",
            "Container uses host network mode",
            "HIGH",
            "network",
            "HostConfig.NetworkMode=host",
            "The container bypasses Docker network isolation and directly shares host networking.",
            "Use bridge or a dedicated Docker network and publish only required ports.",
            "CIS Docker 5.13",
        ))

    findings.extend(published_port_findings(ports))
    return findings


def image_findings(container: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    image = str(get_nested(container, ("Config", "Image"), ""))
    _, tag = normalize_image_tag(image)

    if tag == "latest":
        findings.append(make_finding(
            "unpinned_image_tag",
            "Image tag is not pinned",
            "LOW",
            "image",
            f"Config.Image={image}",
            "The same deployment can resolve to different image contents over time.",
            "Use a versioned tag or immutable digest, for example image:1.2.3 or image@sha256:...",
            "CIS Docker 4.5",
        ))

    if any(name in image.lower() for name in COMMON_SERVICE_IMAGES):
        findings.append(make_finding(
            "common_service_image",
            "Common service image should be checked for CVEs",
            "LOW",
            "image",
            f"Config.Image={image}",
            "Popular service images frequently receive security fixes and should be scanned continuously.",
            "Scan the image with a CVE scanner such as Docker Scout, Trivy, or Grype in CI.",
            "CIS Docker 4.6",
        ))

    return findings


def build_recommended_run(container: dict[str, Any]) -> str:
    image = str(get_nested(container, ("Config", "Image"), "image:tag"))
    user = str(get_nested(container, ("Config", "User"), "") or "10001:10001")
    command = [
        "docker run",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges:true",
        f"--user {user if user not in ('', 'root', '0') else '10001:10001'}",
    ]
    ports = get_nested(container, ("NetworkSettings", "Ports"), {}) or {}
    for container_port, bindings in ports.items():
        if bindings:
            host_port = bindings[0].get("HostPort", container_port.split("/", 1)[0])
            command.append(f"-p 127.0.0.1:{host_port}:{container_port.split('/', 1)[0]}")
    command.append(image)
    return " ".join(command)


def container_state(container: dict[str, Any]) -> dict[str, Any]:
    state = container.get("State") or {}
    host_config = container.get("HostConfig") or {}
    restart_policy = host_config.get("RestartPolicy") or {}
    return {
        "status": state.get("Status", "unknown"),
        "running": bool(state.get("Running", False)),
        "started_at": state.get("StartedAt", ""),
        "finished_at": state.get("FinishedAt", ""),
        "exit_code": state.get("ExitCode"),
        "restart_policy": restart_policy.get("Name", "no"),
    }


def group_findings(findings: list[dict[str, str]]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for category in CATEGORY_ORDER:
        category_findings = [finding for finding in findings if finding["category"] == category]
        if not category_findings:
            continue
        grouped[category] = {
            "overall_risk": calculate_risk(category_findings),
            "total_issues": len(category_findings),
            "findings": category_findings,
        }
    return grouped


def calculate_risk(findings: list[dict[str, str]], score: int | None = None) -> str:
    severities = [finding["severity"] for finding in findings]
    if "CRITICAL" in severities:
        return "CRITICAL"
    computed = sum(SEVERITY_POINTS.get(finding["severity"], 0) for finding in findings) if score is None else score
    high_count = severities.count("HIGH")

    if computed >= 70 or high_count >= 2:
        return "HIGH"
    if computed >= 35 or high_count == 1:
        return "MEDIUM"
    if computed >= 10:
        return "LOW"
    if findings:
        return "LOW"
    return "SAFE"


def score_breakdown(findings: list[dict[str, str]]) -> dict[str, int]:
    breakdown = {category: 0 for category in CATEGORY_ORDER}
    for finding in findings:
        category = finding["category"]
        breakdown[category] = min(100, breakdown.get(category, 0) + SEVERITY_POINTS.get(finding["severity"], 0))
    return {category: score for category, score in breakdown.items() if score > 0}


def cis_checks(findings: list[dict[str, str]]) -> list[dict[str, str]]:
    failed = {finding["cis"]: finding for finding in findings if finding.get("cis")}
    checks: list[dict[str, str]] = []
    for cis, finding in sorted(failed.items()):
        checks.append({
            "id": cis,
            "status": "FAIL",
            "title": finding["title"],
            "severity": finding["severity"],
        })
    return checks


def risk_reasoning(findings: list[dict[str, str]], risk: str) -> str:
    if not findings:
        return "No active findings were detected for this target."
    critical = [finding for finding in findings if finding["severity"] == "CRITICAL"]
    high = [finding for finding in findings if finding["severity"] == "HIGH"]
    if critical:
        return f"This target is {risk} because a critical control failed: {critical[0]['title']}."
    if high:
        return f"This target is {risk} because high-impact findings were detected, led by: {high[0]['title']}."
    top_categories = sorted(score_breakdown(findings).items(), key=lambda item: item[1], reverse=True)
    if top_categories:
        category, score = top_categories[0]
        return f"This target is {risk} mainly due to {category} findings contributing {score} risk points."
    return f"This target is {risk} due to low-level hardening gaps."


def attack_path(findings: list[dict[str, str]]) -> list[str]:
    ids = {finding["id"] for finding in findings}
    path: list[str] = []
    if {"port_public", "sensitive_port_public"} & ids:
        path.append("Publicly reachable service")
    if "secret_in_environment" in ids:
        path.append("Runtime secret exposure")
    if "container_runs_as_root" in ids:
        path.append("Process runs as root")
    if "writable_root_filesystem" in ids:
        path.append("Writable container filesystem")
    if {"extra_capabilities_added", "capabilities_not_dropped"} & ids:
        path.append("Broad Linux capabilities")
    if {"docker_socket_mount", "privileged_container", "host_network_mode", "host_pid_namespace"} & ids:
        path.append("Host impact path")
    return path


def analyze(
    container: dict[str, Any],
    *,
    container_id: str = "",
    policy: dict[str, Any] | None = None,
    ignores: list[dict[str, Any]] | None = None,
    profile: str = "default",
    enable_cve: bool = False,
) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    findings.extend(runtime_findings(container))
    findings.extend(mount_findings(container))
    findings.extend(network_findings(container))
    findings.extend(secret_findings(get_nested(container, ("Config", "Env"), []) or []))
    findings.extend(image_findings(container))
    image = str(get_nested(container, ("Config", "Image"), "unknown"))

    if policy:
        findings.extend(policy_engine.container_policy_findings(container, policy, profile))

    cve_findings, cve_status = cve.scan_image(image, enabled=enable_cve)
    findings.extend(cve_findings)

    if is_tool_image(image):
        for finding in findings:
            if finding["severity"] == "MEDIUM" and finding["category"] in {"runtime", "image"}:
                finding["severity"] = "LOW"
                finding["risk"] = "LOW"

    target = {"id": container_id, "image": image}
    findings, suppressed_findings = policy_engine.apply_ignores(findings, ignores or [], target)
    total_score = min(100, sum(SEVERITY_POINTS.get(finding["severity"], 0) for finding in findings))
    risk = calculate_risk(findings, total_score)
    issues = [f"{finding['severity']}: {finding['title']}" for finding in findings]

    return {
        "image": image,
        "user": get_nested(container, ("Config", "User"), ""),
        "runtime_status": str(get_nested(container, ("State", "Status"), "unknown")),
        "docker_state": container_state(container),
        "risk": risk,
        "score": total_score,
        "risk_reasoning": risk_reasoning(findings, risk),
        "attack_path": attack_path(findings),
        "score_breakdown": score_breakdown(findings),
        "issues": issues,
        "findings": findings,
        "suppressed_findings": suppressed_findings,
        "findings_by_category": group_findings(findings),
        "cis_checks": cis_checks(findings),
        "recommended_run": build_recommended_run(container),
        "cve_scan": cve_status,
    }


def analyze_dockerfile(path: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if not path.exists():
        return findings

    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    has_user = False
    for number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        upper = line.upper()
        if not line or line.startswith("#"):
            continue
        if upper.startswith("FROM "):
            image = line.split(None, 1)[1].split(" AS ", 1)[0].strip()
            _, tag = normalize_image_tag(image)
            if tag == "latest":
                findings.append(make_finding(
                    "dockerfile_unpinned_from",
                    "Dockerfile base image is not pinned",
                    "MEDIUM",
                    "dockerfile",
                    f"{path}:{number}: {line}",
                    "Builds may change unexpectedly when the upstream image tag changes.",
                    "Pin the base image to a version tag or immutable digest.",
                    "CIS Docker 4.5",
                ))
        if upper.startswith("USER "):
            has_user = True
            user = line.split(None, 1)[1].strip()
            if user in ("root", "0"):
                findings.append(make_finding(
                    "dockerfile_root_user",
                    "Dockerfile explicitly selects root user",
                    "HIGH",
                    "dockerfile",
                    f"{path}:{number}: {line}",
                    "The resulting image is expected to run with root privileges.",
                    "Create and switch to a non-root application user.",
                    "CIS Docker 4.1",
                ))
        if upper.startswith("ADD "):
            findings.append(make_finding(
                "dockerfile_add_used",
                "Dockerfile uses ADD",
                "LOW",
                "dockerfile",
                f"{path}:{number}: {line}",
                "ADD has extra remote URL and archive extraction behavior that can surprise builds.",
                "Use COPY unless ADD-specific behavior is required and documented.",
                "CIS Docker 4.9",
            ))
        if upper.startswith("ENV "):
            key_value = line.split(None, 1)[1]
            key = re.split(r"\s+|=", key_value, maxsplit=1)[0]
            if any(pattern in key.upper() for pattern in SENSITIVE_ENV_PATTERNS):
                findings.append(make_finding(
                    "dockerfile_secret_env",
                    "Potential secret is defined in Dockerfile ENV",
                    "HIGH",
                    "dockerfile",
                    f"{path}:{number}: ENV {key}=***",
                    "Secrets baked into images can be recovered from image history or runtime metadata.",
                    "Inject secrets at runtime using Docker secrets or a secret manager.",
                    "CIS Docker 4.10",
                ))
        if "curl " in line and "| sh" in line:
            findings.append(make_finding(
                "dockerfile_curl_pipe_shell",
                "Dockerfile pipes remote script into shell",
                "HIGH",
                "dockerfile",
                f"{path}:{number}: {line}",
                "Builds execute remote content without integrity verification.",
                "Download pinned artifacts, verify checksums or signatures, then execute locally.",
                "CIS Docker 4.8",
            ))

    if not has_user:
        findings.append(make_finding(
            "dockerfile_user_missing",
            "Dockerfile does not define a non-root USER",
            "HIGH",
            "dockerfile",
            f"{path}: no USER instruction found",
            "Images without USER usually run as root by default.",
            "Create a dedicated user and add USER before the final CMD or ENTRYPOINT.",
            "CIS Docker 4.1",
        ))

    return findings


def analyze_compose(path: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if not path.exists():
        return findings

    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    for number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        lower = line.lower()
        if not line or line.startswith("#"):
            continue
        checks = [
            ("privileged: true", "compose_privileged", "Compose enables privileged mode", "CRITICAL", "Remove privileged: true and grant only required capabilities."),
            ("network_mode: host", "compose_host_network", "Compose uses host network mode", "HIGH", "Use bridge or a dedicated Docker network."),
            ("pid: host", "compose_host_pid", "Compose shares host PID namespace", "HIGH", "Avoid pid: host unless this is a monitoring workload."),
            ("ipc: host", "compose_host_ipc", "Compose shares host IPC namespace", "HIGH", "Avoid ipc: host unless explicitly required."),
        ]
        for token, finding_id, title, severity, recommendation in checks:
            if token in lower:
                findings.append(make_finding(
                    finding_id,
                    title,
                    severity,
                    "compose",
                    f"{path}:{number}: {line}",
                    "The Compose configuration weakens container isolation.",
                    recommendation,
                    "CIS Docker 5",
                ))
        if "/var/run/docker.sock" in lower:
            findings.append(make_finding(
                "compose_docker_socket",
                "Compose mounts the Docker socket",
                "CRITICAL",
                "compose",
                f"{path}:{number}: {line}",
                "Services with Docker socket access can control the Docker daemon.",
                "Remove the docker.sock mount or use a restricted proxy.",
                "CIS Docker 5.31",
            ))
        if re.search(r":\s*latest\b|image:\s*[^@\s:]+$", line, flags=re.IGNORECASE):
            findings.append(make_finding(
                "compose_unpinned_image",
                "Compose image tag is not pinned",
                "MEDIUM",
                "compose",
                f"{path}:{number}: {line}",
                "Deployments may pull different image contents over time.",
                "Pin image references to version tags or immutable digests.",
                "CIS Docker 4.5",
            ))

    return findings


def analyze_project_files(
    root: Path,
    *,
    policy: dict[str, Any] | None = None,
    ignores: list[dict[str, Any]] | None = None,
    profile: str = "default",
) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    findings.extend(analyze_dockerfile(root / "Dockerfile"))
    for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        findings.extend(analyze_compose(root / name))
    if policy:
        findings.extend(policy_engine.project_policy_findings(root, policy, profile))

    findings, suppressed_findings = policy_engine.apply_ignores(findings, ignores or [], {"id": "project", "image": ""})
    score = min(100, sum(SEVERITY_POINTS.get(finding["severity"], 0) for finding in findings))
    risk = calculate_risk(findings, score)
    return {
        "risk": risk,
        "score": score,
        "risk_reasoning": risk_reasoning(findings, risk),
        "total_findings": len(findings),
        "findings": findings,
        "suppressed_findings": suppressed_findings,
        "findings_by_category": group_findings(findings),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Docker Security Analyzer")
    parser.add_argument("--profile", default="default", help="Policy profile name, e.g. default, dev, production")
    parser.add_argument("--enable-cve", action="store_true", help="Run Trivy or Grype if installed")
    parser.add_argument("--no-docker", action="store_true", help="Scan repository files only")
    parser.add_argument("--include-stopped", action="store_true", help="Scan stopped containers too by using docker ps --all")
    parser.add_argument("--fail-on", default="", help="Exit non-zero when this severity or higher is found")
    parser.add_argument("--write-exports", action="store_true", help="Write SARIF, Markdown and CSV reports")
    return parser.parse_args()


def write_exports(report: dict[str, Any], root: Path) -> None:
    (root / "report.sarif").write_text(exporters.to_json_text(exporters.to_sarif(report)), encoding="utf-8")
    (root / "report.md").write_text(exporters.to_markdown(report), encoding="utf-8")
    (root / "report.csv").write_text(exporters.to_csv(report), encoding="utf-8")


def main() -> None:
    args = parse_args()
    root = Path.cwd()
    loaded_policy = policy_engine.load_policy(root)
    loaded_ignores = policy_engine.load_ignores(root)
    profile = args.profile
    report: dict[str, Any] = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "containers": [],
        "project_files": analyze_project_files(
            root,
            policy=loaded_policy,
            ignores=loaded_ignores,
            profile=profile,
        ),
        "policy": {
            "profile": profile,
            "profile_config": policy_engine.profile_config(loaded_policy, profile),
            "ignore_rules": len(loaded_ignores),
        },
        "docker": {
            "mode": "skipped" if args.no_docker else ("all" if args.include_stopped else "running"),
            "include_stopped": args.include_stopped,
            "container_count": 0,
        },
        "scanner": {
            "name": "docker-security-analyzer",
            "version": "3.1",
            "cve": cve.scanner_status(),
        },
    }

    if args.no_docker:
        containers = []
        report["scan_error"] = "Docker runtime scan skipped by --no-docker."
    else:
        try:
            containers = get_containers(include_stopped=args.include_stopped)
        except RuntimeError as exc:
            report["scan_error"] = str(exc)
            containers = []

    report["docker"]["container_count"] = len(containers)

    for cid in containers:
        try:
            data = inspect_container(cid)
            result = analyze(
                data,
                container_id=cid,
                policy=loaded_policy,
                ignores=loaded_ignores,
                profile=profile,
                enable_cve=args.enable_cve,
            )
            report["containers"].append({"id": cid, **result})
        except (RuntimeError, json.JSONDecodeError) as exc:
            report["containers"].append({
                "id": cid,
                "image": "unknown",
                "user": "",
                "runtime_status": "unknown",
                "docker_state": {"status": "unknown", "running": False},
                "risk": "CRITICAL",
                "score": 100,
                "issues": [f"CRITICAL: Container could not be inspected: {exc}"],
                "findings": [make_finding(
                    "inspect_failed",
                    "Container could not be inspected",
                    "CRITICAL",
                    "runtime",
                    str(exc),
                    "The scanner cannot assess the container security posture without inspect data.",
                    "Check Docker daemon permissions and rerun the scan.",
                )],
            })

    gate_result = gate.evaluate_gate(report, args.fail_on or "CRITICAL")
    report["gate"] = gate_result

    with Path("report.json").open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=4)
    if args.write_exports:
        write_exports(report, root)

    if not containers and not args.no_docker:
        if args.include_stopped:
            print("No containers found.")
        else:
            print("No running containers found.")
    print(f"Report saved to report.json ({len(report['containers'])} containers)")
    if args.write_exports:
        print("Exports saved to report.sarif, report.md and report.csv")
    if report.get("scan_error"):
        print(f"Docker scan warning: {report['scan_error']}")
    if args.fail_on and not gate_result["passed"]:
        print(f"Security gate failed on {args.fail_on.upper()} ({gate_result['blocking_findings']} blocking findings)")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
