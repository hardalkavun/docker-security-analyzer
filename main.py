import subprocess
import json
import os

REPORT_FILE = "report.json"

def get_containers():
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.ID}}"],
        capture_output=True,
        text=True
    )

    containers = result.stdout.strip().split("\n")
    return [c for c in containers if c]

def inspect_container(cid):
    result = subprocess.run(
        ["docker", "inspect", cid],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)[0]

def analyze(container):
    issues = []

    image = container["Config"]["Image"]
    user = container["Config"]["User"]

    # Root check
    if user == "" or user == "root":
        issues.append(("Running as root", "HIGH"))

    # Latest tag check
    if ":latest" in image:
        issues.append(("Using latest tag", "MEDIUM"))

    # Privileged mode
    if container["HostConfig"].get("Privileged", False):
        issues.append(("Privileged mode enabled", "HIGH"))

    # Exposed ports
    if container["NetworkSettings"].get("Ports"):
        issues.append(("Exposed ports", "MEDIUM"))

    # Docker socket mount (critical)
    binds = container["HostConfig"].get("Binds") or []
    if any("docker.sock" in b for b in binds):
        issues.append(("Docker socket mounted", "HIGH"))

    return issues

def get_risk_level(issues):
    if not issues:
        return "LOW"

    has_high = any(i[1] == "HIGH" for i in issues)
    has_medium = any(i[1] == "MEDIUM" for i in issues)

    if has_high:
        return "HIGH"
    elif has_medium:
        return "MEDIUM"
    return "LOW"

def color(risk):
    if risk == "LOW":
        return " LOW"
    elif risk == "MEDIUM":
        return " MEDIUM"
    else:
        return " HIGH"

def save_report(report):
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=4)

def main():
    containers = get_containers()

    if not containers:
        print("No running containers found.")
        return

    report = {
        "containers": [],
        "summary": {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    }

    for cid in containers:
        data = inspect_container(cid)
        issues = analyze(data)
        risk = get_risk_level(issues)

        report["summary"][risk] += 1

        container_report = {
            "id": cid,
            "image": data["Config"]["Image"],
            "risk": risk,
            "issues": [i[0] for i in issues]
        }

        report["containers"].append(container_report)

        print("\n====================")
        print("Container:", cid)
        print("Image:", data["Config"]["Image"])
        print("Risk:", color(risk))

        if issues:
            print("Issues:")
            for i in issues:
                print("-", i[0])
        else:
            print("No issues found")

    print("\n====================")
    print("SUMMARY")
    print("LOW:", report["summary"]["LOW"])
    print("MEDIUM:", report["summary"]["MEDIUM"])
    print("HIGH:", report["summary"]["HIGH"])

    save_report(report)
    print("\nReport saved to report.json")

if __name__ == "__main__":
    main()