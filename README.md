# Docker Security Analyzer

Evidence-based Docker workload security analyzer with runtime checks, repository file scanning, policy rules, remediation output, CI gates, and multiple export formats.

## Highlights

- Docker runtime inspection for root user, privileged mode, host namespaces, capabilities, read-only filesystem, Docker socket mounts, sensitive mounts, public ports, and leaked environment secrets.
- Dockerfile and Compose scanning for risky build and deployment patterns.
- Policy-driven rules through `security-policy.json`.
- Ignore management through `.docker-security-ignore.json` with expiry dates and reasons.
- Optional CVE adapter for Trivy or Grype when either tool is installed.
- Risk reasoning, attack path hints, CIS-style references, and generated hardened `docker run` commands.
- Export formats: JSON, HTML, SARIF, Markdown, and CSV.
- GitHub Actions security gate with SARIF upload.

## Usage

Run a local Docker scan:

```bash
python main.py
```

Scan repository files only, useful for CI:

```bash
python main.py --no-docker --profile production --fail-on HIGH --write-exports
```

Enable CVE scanning when Trivy or Grype is installed:

```bash
python main.py --enable-cve
```

Start the dashboard:

```bash
python app.py
```

Then open `http://127.0.0.1:5000/`.

## Dashboard Exports

- `/export/json`
- `/export/html`
- `/export/sarif`
- `/export/csv`
- `/export/markdown`

## Policy

`security-policy.json` contains profile-aware container and project rules. The scanner supports rules such as host config equality checks, Docker socket mount checks, secret-like environment variables, and repository file checks.

## Ignore File

`.docker-security-ignore.json` suppresses known acceptable findings. Each ignore should include a reason and an expiry date so exceptions do not become permanent blind spots.

## Tests

```bash
python -m unittest
```
"# docker-security-analyzer" 




<img width="1920" height="955" alt="image" src="https://github.com/user-attachments/assets/003e788b-a458-49da-9afe-bb7972607ef1" />
<img width="1072" height="953" alt="image" src="https://github.com/user-attachments/assets/74fb35ca-0f16-488f-8cfe-76e99646960c" />
