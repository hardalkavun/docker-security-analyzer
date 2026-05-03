from __future__ import annotations

import copy
import json
import logging
from pathlib import Path
from typing import Any

from flask import Flask, Response, abort, render_template_string, request, send_file
from scanner import exporters

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

REPORT_PATH = Path(__file__).with_name("report.json")
RISK_LEVELS = ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
RISK_COLORS = {
    "CRITICAL": "#b91c1c",
    "HIGH": "#c2410c",
    "MEDIUM": "#ca8a04",
    "LOW": "#15803d",
    "SAFE": "#2563eb",
}


def get_risk_color(risk: str | None) -> str:
    return RISK_COLORS.get((risk or "").upper(), "#64748b")


def load_report() -> tuple[dict[str, Any], str | None]:
    if not REPORT_PATH.exists():
        return {"containers": [], "project_files": {"findings": []}}, "report.json bulunamadi. Once tarama calistirilmalidir."

    try:
        with REPORT_PATH.open(encoding="utf-8") as report_file:
            data = json.load(report_file)
    except json.JSONDecodeError:
        app.logger.exception("report.json okunamadi: gecersiz JSON")
        return {"containers": [], "project_files": {"findings": []}}, "report.json gecersiz JSON iceriyor."
    except OSError:
        app.logger.exception("report.json okunurken hata olustu")
        return {"containers": [], "project_files": {"findings": []}}, "report.json okunurken bir hata olustu."

    if not isinstance(data, dict):
        return {"containers": [], "project_files": {"findings": []}}, "report.json beklenen sozluk formatinda degil."
    if not isinstance(data.get("containers"), list):
        data["containers"] = []
    if not isinstance(data.get("project_files"), dict):
        data["project_files"] = {"findings": []}
    return data, None


def normalize_filter(raw_filter: str | None) -> str:
    value = (raw_filter or "").upper()
    return value if value in RISK_LEVELS else ""


def finding_class(finding: dict[str, Any] | str) -> str:
    if isinstance(finding, dict):
        return str(finding.get("severity") or finding.get("risk") or "LOW").lower()
    text = finding.upper()
    if "CRITICAL" in text:
        return "critical"
    if "HIGH" in text:
        return "high"
    if "MEDIUM" in text:
        return "medium"
    return "low"


def flatten_category_findings(category_data: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not category_data:
        return []
    findings = category_data.get("findings", [])
    if isinstance(findings, list):
        return [finding for finding in findings if isinstance(finding, dict)]
    if isinstance(findings, dict):
        flattened: list[dict[str, Any]] = []
        for value in findings.values():
            if isinstance(value, list):
                flattened.extend(item for item in value if isinstance(item, dict))
            elif isinstance(value, dict):
                flattened.append(value)
        return flattened
    return []


def summarize(containers: list[dict[str, Any]]) -> dict[str, int]:
    summary = {level: 0 for level in RISK_LEVELS}
    for container in containers:
        risk = str(container.get("risk", "SAFE")).upper()
        if risk in summary:
            summary[risk] += 1
    return summary


def collect_remediations(container: dict[str, Any]) -> list[str]:
    remediations: list[str] = []
    for finding in container.get("findings", []):
        recommendation = finding.get("recommendation") if isinstance(finding, dict) else None
        if recommendation and recommendation not in remediations:
            remediations.append(recommendation)
    return remediations


BASE_CSS = """
<style>
    :root {
        --bg: #eef2f7;
        --panel: #ffffff;
        --panel-muted: #f8fafc;
        --text: #172033;
        --muted: #64748b;
        --border: #dbe3ef;
        --accent: #2563eb;
        --shadow: 0 18px 45px rgba(15, 23, 42, 0.10);
    }
    * { box-sizing: border-box; }
    body {
        margin: 0;
        min-height: 100vh;
        background: var(--bg);
        color: var(--text);
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .topbar { background: #111827; color: #fff; padding: 28px 20px; border-bottom: 4px solid #38bdf8; }
    .container { max-width: 1220px; margin: 0 auto; padding: 0 20px; }
    .page { padding-top: 24px; padding-bottom: 40px; }
    h1 { margin: 0; font-size: clamp(28px, 4vw, 42px); letter-spacing: 0; }
    h2 { margin: 0 0 12px; font-size: 18px; }
    h3 { margin: 0 0 8px; font-size: 16px; }
    .subtitle { margin-top: 8px; color: #cbd5e1; }
    .toolbar, .card, .summary-item {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 8px;
        box-shadow: var(--shadow);
    }
    .toolbar { display: flex; justify-content: space-between; gap: 16px; align-items: center; padding: 16px; margin-bottom: 18px; }
    .actions, .filter-form { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    label { color: var(--muted); font-weight: 700; font-size: 14px; }
    select, button, .button {
        min-height: 40px;
        border-radius: 8px;
        border: 1px solid var(--border);
        background: #fff;
        color: var(--text);
        font: inherit;
        padding: 0 14px;
    }
    button, .button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        border-color: var(--accent);
        background: var(--accent);
        color: #fff;
        cursor: pointer;
        text-decoration: none;
        font-weight: 700;
    }
    .button.secondary { background: #fff; color: var(--accent); }
    .scan-info, .meta { color: var(--muted); font-size: 14px; }
    .notice {
        margin-bottom: 18px;
        border: 1px solid #f59e0b;
        background: #fffbeb;
        color: #92400e;
        border-radius: 8px;
        padding: 12px 14px;
    }
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(145px, 1fr)); gap: 12px; margin-bottom: 18px; }
    .summary-item { padding: 14px; box-shadow: none; }
    .summary-label { color: var(--muted); font-size: 12px; font-weight: 800; text-transform: uppercase; }
    .summary-value { margin-top: 5px; font-size: 24px; font-weight: 800; }
    .card { margin-bottom: 14px; overflow: hidden; }
    .card-header { display: flex; justify-content: space-between; gap: 16px; align-items: center; padding: 18px; cursor: pointer; background: #fff; }
    .card-header:hover { background: var(--panel-muted); }
    .card-title { font-size: 19px; font-weight: 800; }
    .details { display: none; border-top: 1px solid var(--border); padding: 18px; background: #fff; }
    .details.open { display: block; }
    .risk-badge {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 96px;
        min-height: 32px;
        border-radius: 999px;
        color: white;
        font-weight: 800;
        font-size: 12px;
        text-transform: uppercase;
    }
    .score { color: var(--muted); text-align: right; margin-top: 6px; font-weight: 700; }
    code, pre {
        background: #eef2f7;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        word-break: break-word;
    }
    code { padding: 2px 6px; }
    pre { margin: 8px 0 0; padding: 10px; white-space: pre-wrap; }
    .grid-two { display: grid; grid-template-columns: minmax(0, 1fr) minmax(280px, 0.45fr); gap: 14px; }
    .finding {
        border: 1px solid var(--border);
        border-left-width: 5px;
        border-radius: 8px;
        background: var(--panel-muted);
        padding: 12px;
        margin-top: 10px;
    }
    .critical { border-left-color: #b91c1c; }
    .high { border-left-color: #c2410c; }
    .medium { border-left-color: #ca8a04; }
    .low { border-left-color: #15803d; }
    .tabs { display: flex; gap: 8px; flex-wrap: wrap; margin: 10px 0 14px; }
    .tab-button { min-height: 36px; border-color: var(--border); background: #f8fafc; color: var(--text); font-size: 13px; }
    .tab-button.active { border-color: var(--accent); background: var(--accent); color: #fff; }
    .tab-content { display: none; border: 1px solid var(--border); border-radius: 8px; padding: 14px; }
    .tab-content.active { display: block; }
    .breakdown { display: grid; gap: 8px; }
    .bar { height: 8px; background: #e2e8f0; border-radius: 999px; overflow: hidden; }
    .bar span { display: block; height: 100%; background: var(--accent); }
    .compact-list { margin: 0; padding-left: 18px; }
    .compact-list li { margin: 8px 0; }
    .project-panel { padding: 18px; margin-bottom: 18px; }
    .empty { color: var(--muted); padding: 18px; text-align: center; }
    @media (max-width: 820px) {
        .toolbar, .card-header { align-items: flex-start; flex-direction: column; }
        .grid-two { grid-template-columns: 1fr; }
        .score { text-align: left; }
        .container { padding: 0 14px; }
    }
</style>
"""


FINDING_PARTIAL = """
{% for finding in findings %}
<div class="finding {{ finding_class(finding) }}">
    <h3>{{ finding.get('title', 'Finding') }}</h3>
    <div class="meta">
        {{ finding.get('severity', 'LOW') }}{% if finding.get('category') %} / {{ finding.get('category') }}{% endif %}
        {% if finding.get('cis') %} / {{ finding.get('cis') }}{% endif %}
    </div>
    {% if finding.get('evidence') %}<p><strong>Evidence:</strong> <code>{{ finding.get('evidence') }}</code></p>{% endif %}
    {% if finding.get('impact') %}<p><strong>Impact:</strong> {{ finding.get('impact') }}</p>{% endif %}
    {% if finding.get('recommendation') %}<p><strong>Fix:</strong> {{ finding.get('recommendation') }}</p>{% endif %}
</div>
{% endfor %}
"""


HTML = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Docker Security Dashboard</title>
    """ + BASE_CSS + """
</head>
<body>
    <header class="topbar">
        <div class="container">
            <h1>Docker Security Dashboard</h1>
            <div class="subtitle">Evidence-based container, Dockerfile, and Compose security findings</div>
        </div>
    </header>

    <main class="container page">
        {% if error_message %}<div class="notice">{{ error_message }}</div>{% endif %}
        {% if data.get('scan_error') %}<div class="notice">Docker scan warning: {{ data.get('scan_error') }}</div>{% endif %}

        <div class="toolbar">
            <form class="filter-form" method="GET">
                <label for="filter">Risk Filter</label>
                <select name="filter" id="filter">
                    <option value="" {% if filter_value == '' %}selected{% endif %}>ALL</option>
                    {% for level in risk_levels %}
                    <option value="{{ level }}" {% if filter_value == level %}selected{% endif %}>{{ level }}</option>
                    {% endfor %}
                </select>
                <button type="submit">Filter</button>
            </form>
            <div class="actions">
                <a class="button secondary" href="/export/json">JSON Export</a>
                <a class="button secondary" href="/export/html">HTML Export</a>
                <a class="button secondary" href="/export/sarif">SARIF</a>
                <a class="button secondary" href="/export/csv">CSV</a>
                <a class="button secondary" href="/export/markdown">Markdown</a>
            </div>
            <div class="scan-info">
                {% if data.get('scan_timestamp') %}Last scanned: {{ data['scan_timestamp'] }}{% else %}Scan timestamp unavailable{% endif %}
            </div>
        </div>

        <section class="summary-grid" aria-label="Risk summary">
            <div class="summary-item"><div class="summary-label">Containers</div><div class="summary-value">{{ containers|length }}</div></div>
            {% for level in risk_levels %}
            <div class="summary-item"><div class="summary-label">{{ level }}</div><div class="summary-value" style="color: {{ get_risk_color(level) }}">{{ summary.get(level, 0) }}</div></div>
            {% endfor %}
        </section>

        <section class="card project-panel">
            <div class="card-title">Project File Analysis</div>
            <div class="meta">Dockerfile and Compose checks from this repository</div>
            {% set project = data.get('project_files', {}) %}
            <p><strong>Risk:</strong> <span class="risk-badge" style="background-color: {{ get_risk_color(project.get('risk')) }}">{{ project.get('risk', 'SAFE') }}</span>
            <strong>Findings:</strong> {{ project.get('total_findings', project.get('findings', [])|length) }}</p>
            {% if project.get('risk_reasoning') %}<p><strong>Reasoning:</strong> {{ project.get('risk_reasoning') }}</p>{% endif %}
            {% if project.get('findings') %}
                {% set findings = project.get('findings')[:8] %}
                """ + FINDING_PARTIAL + """
            {% else %}
                <p class="empty">No Dockerfile or Compose findings detected.</p>
            {% endif %}
        </section>

        {% if containers|length == 0 %}
        <div class="card"><p class="empty">No containers found for the selected filter.</p></div>
        {% endif %}

        {% for c in containers %}
        {% set container_key = 'container-' ~ loop.index %}
        <article class="card">
            <div class="card-header" role="button" tabindex="0" aria-expanded="false" aria-controls="{{ container_key }}" onclick="toggleDetails(this, '{{ container_key }}')" onkeydown="handleCardKey(event, this, '{{ container_key }}')">
                <div>
                    <div class="card-title">{{ c.get("id", "")[:12] or "unknown" }}</div>
                    <div class="meta">Image: <code>{{ c.get("image", "unknown") }}</code></div>
                    <div class="meta">User: <code>{{ c.get("user") or "root" }}</code></div>
                </div>
                <div>
                    <div class="risk-badge" style="background-color: {{ get_risk_color(c.get('risk')) }};">{{ c.get("risk", "SAFE") }}</div>
                    <div class="score">Score {{ c.get("score", 0) }}/100</div>
                </div>
            </div>

            <div id="{{ container_key }}" class="details">
                <div class="grid-two">
                    <div>
                        <h2>Evidence-Based Findings ({{ c.get('findings', [])|length }})</h2>
                        {% if c.get('findings_by_category') %}
                        <div class="tabs" data-tab-group="{{ container_key }}">
                            {% for category, category_data in c.get('findings_by_category', {}).items() %}
                            {% set tab_id = container_key ~ '-tab-' ~ loop.index %}
                            <button type="button" class="tab-button {% if loop.first %}active{% endif %}" onclick="switchTab('{{ container_key }}', '{{ tab_id }}', this)">
                                {{ category.replace('_', ' ').title() }} ({{ category_data.get('total_issues', 0) }})
                            </button>
                            {% endfor %}
                        </div>
                        {% for category, category_data in c.get('findings_by_category', {}).items() %}
                        {% set tab_id = container_key ~ '-tab-' ~ loop.index %}
                        <section id="{{ tab_id }}" class="tab-content {% if loop.first %}active{% endif %}" data-tab-group="{{ container_key }}">
                            <p><strong>Category Risk:</strong> <span class="risk-badge" style="background-color: {{ get_risk_color(category_data.get('overall_risk')) }}">{{ category_data.get('overall_risk', 'SAFE') }}</span></p>
                            {% set findings = flatten_category_findings(category_data) %}
                            """ + FINDING_PARTIAL + """
                        </section>
                        {% endfor %}
                        {% else %}
                        <p class="empty">No findings for this container.</p>
                        {% endif %}
                    </div>

                    <aside>
                        <h2>Score Breakdown</h2>
                        {% if c.get('risk_reasoning') %}<p><strong>Reasoning:</strong> {{ c.get('risk_reasoning') }}</p>{% endif %}
                        {% if c.get('attack_path') %}
                        <h2 style="margin-top: 18px;">Attack Path</h2>
                        <ol class="compact-list">
                            {% for step in c.get('attack_path', []) %}<li>{{ step }}</li>{% endfor %}
                        </ol>
                        {% endif %}
                        <div class="breakdown">
                            {% for category, score in c.get('score_breakdown', {}).items() %}
                            <div>
                                <div class="meta">{{ category.replace('_', ' ').title() }}: {{ score }}</div>
                                <div class="bar"><span style="width: {{ score }}%"></span></div>
                            </div>
                            {% endfor %}
                            {% if not c.get('score_breakdown') %}<p class="empty">No risk points assigned.</p>{% endif %}
                        </div>

                        <h2 style="margin-top: 18px;">Recommended Run</h2>
                        {% if c.get('recommended_run') %}<pre>{{ c.get('recommended_run') }}</pre>{% else %}<p class="empty">No command generated.</p>{% endif %}

                        <h2 style="margin-top: 18px;">Remediation Checklist</h2>
                        {% set remediations = collect_remediations(c) %}
                        {% if remediations %}
                        <ul class="compact-list">
                            {% for item in remediations[:8] %}<li>{{ item }}</li>{% endfor %}
                        </ul>
                        {% else %}
                        <p class="empty">No remediation needed.</p>
                        {% endif %}

                        <h2 style="margin-top: 18px;">CIS-Style Checks</h2>
                        {% if c.get('cis_checks') %}
                        <ul class="compact-list">
                            {% for check in c.get('cis_checks', [])[:8] %}
                            <li><strong>{{ check.get('status') }}</strong> {{ check.get('id') }}: {{ check.get('title') }}</li>
                            {% endfor %}
                        </ul>
                        {% else %}
                        <p class="empty">No failed CIS-style checks.</p>
                        {% endif %}

                        <h2 style="margin-top: 18px;">CVE Scan</h2>
                        {% set cve_scan = c.get('cve_scan', {}) %}
                        <p class="meta">{{ cve_scan.get('tool', 'none') }} / {{ cve_scan.get('status', 'unknown') }}</p>

                        <p style="margin-top: 18px;"><a class="button" href="/container/{{ c.get('id') }}">View Full Details</a></p>
                    </aside>
                </div>
            </div>
        </article>
        {% endfor %}
    </main>

    <script>
        function toggleDetails(header, id) {
            const elem = document.getElementById(id);
            const isOpen = elem.classList.toggle('open');
            header.setAttribute('aria-expanded', String(isOpen));
        }
        function handleCardKey(event, header, id) {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                toggleDetails(header, id);
            }
        }
        function switchTab(groupId, tabId, button) {
            document.querySelectorAll('[data-tab-group="' + groupId + '"].tab-content').forEach(function(tab) {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tabs[data-tab-group="' + groupId + '"] .tab-button').forEach(function(tabButton) {
                tabButton.classList.remove('active');
            });
            document.getElementById(tabId).classList.add('active');
            button.classList.add('active');
        }
    </script>
</body>
</html>
"""


DETAIL_HTML = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Container Details</title>
    """ + BASE_CSS + """
</head>
<body>
    <header class="topbar">
        <div class="container">
            <h1>Container Details: {{ c.get("id", "")[:12] }}</h1>
            <div class="subtitle">{{ c.get("image", "unknown") }}</div>
        </div>
    </header>

    <main class="container page">
        <section class="card project-panel">
            <h2>Basic Information</h2>
            <p><strong>User:</strong> <code>{{ c.get("user") or "root" }}</code></p>
            <p><strong>Risk Level:</strong> <span class="risk-badge" style="background-color: {{ get_risk_color(c.get('risk')) }}">{{ c.get("risk", "SAFE") }}</span></p>
            <p><strong>Security Score:</strong> {{ c.get("score", 0) }}/100</p>
            {% if c.get('risk_reasoning') %}<p><strong>Reasoning:</strong> {{ c.get('risk_reasoning') }}</p>{% endif %}
            {% if c.get('attack_path') %}
            <h2>Attack Path</h2>
            <ol class="compact-list">
                {% for step in c.get('attack_path', []) %}<li>{{ step }}</li>{% endfor %}
            </ol>
            {% endif %}
            {% if c.get('recommended_run') %}<h2>Recommended Run</h2><pre>{{ c.get('recommended_run') }}</pre>{% endif %}
        </section>

        <section class="card project-panel">
            <h2>All Findings</h2>
            {% set findings = c.get('findings', []) %}
            {% if findings %}
                """ + FINDING_PARTIAL + """
            {% else %}
                <p class="empty">No findings for this container.</p>
            {% endif %}
        </section>

        <a class="button" href="/">Back to Dashboard</a>
    </main>
</body>
</html>
"""


@app.route("/")
def index():
    data, error_message = load_report()
    containers = copy.deepcopy(data.get("containers", []))
    filter_value = normalize_filter(request.args.get("filter"))
    if filter_value:
        containers = [c for c in containers if str(c.get("risk", "")).upper() == filter_value]

    return render_template_string(
        HTML,
        data=data,
        containers=containers,
        summary=summarize(containers),
        risk_levels=RISK_LEVELS,
        get_risk_color=get_risk_color,
        finding_class=finding_class,
        flatten_category_findings=flatten_category_findings,
        collect_remediations=collect_remediations,
        filter_value=filter_value,
        error_message=error_message,
    )


@app.route("/container/<cid>")
def container_detail(cid: str):
    data, _ = load_report()
    container = next((c for c in data.get("containers", []) if c.get("id") == cid), None)
    if container is None:
        abort(404, description="Container not found")
    return render_template_string(
        DETAIL_HTML,
        c=container,
        get_risk_color=get_risk_color,
        finding_class=finding_class,
    )


@app.route("/export/json")
def export_json():
    if not REPORT_PATH.exists():
        abort(404, description="report.json not found")
    return send_file(REPORT_PATH, as_attachment=True, download_name="docker-security-report.json")


@app.route("/export/html")
def export_html():
    data, error_message = load_report()
    rendered = render_template_string(
        HTML,
        data=data,
        containers=data.get("containers", []),
        summary=summarize(data.get("containers", [])),
        risk_levels=RISK_LEVELS,
        get_risk_color=get_risk_color,
        finding_class=finding_class,
        flatten_category_findings=flatten_category_findings,
        collect_remediations=collect_remediations,
        filter_value="",
        error_message=error_message,
    )
    return Response(
        rendered,
        headers={"Content-Disposition": "attachment; filename=docker-security-report.html"},
        mimetype="text/html",
    )


@app.route("/export/sarif")
def export_sarif():
    data, _ = load_report()
    return Response(
        exporters.to_json_text(exporters.to_sarif(data)),
        headers={"Content-Disposition": "attachment; filename=docker-security-report.sarif"},
        mimetype="application/sarif+json",
    )


@app.route("/export/csv")
def export_csv():
    data, _ = load_report()
    return Response(
        exporters.to_csv(data),
        headers={"Content-Disposition": "attachment; filename=docker-security-report.csv"},
        mimetype="text/csv",
    )


@app.route("/export/markdown")
def export_markdown():
    data, _ = load_report()
    return Response(
        exporters.to_markdown(data),
        headers={"Content-Disposition": "attachment; filename=docker-security-report.md"},
        mimetype="text/markdown",
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
