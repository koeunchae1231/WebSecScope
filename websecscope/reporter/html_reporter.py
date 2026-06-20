from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any

from websecscope.i18n import normalize_language, severity_label, text
from websecscope.reporter.llm_report_generator import LLMReportRequest, generate_llm_report
from websecscope.utils import ensure_parent
from websecscope.visualizer.html import score_class, status_class

AI_REPORT_NOTICE = (
    "Findings were detected by the rule-based engine. "
    "The LLM only summarized and explained the results."
)


def write_html_report(
    result: dict[str, Any],
    output_path: str | Path,
    language: str | None = None,
) -> Path:
    output = ensure_parent(output_path)
    lang = normalize_language(language or result.get("language"))
    result["language"] = lang
    findings = result.get("all_findings", result.get("findings", []))
    summary = result.get("findings_summary", {})
    rows = "\n".join(_finding_row(finding) for finding in findings)
    executive_section = _executive_section(result, summary)
    severity_section = _severity_section(summary)
    top_risks_section = _top_risks_section(summary.get("top_risks", []))
    finding_sections = render_findings_sections(findings)
    web_section = _category_section(text("web_security", lang), findings, {"web"})
    api_section = _category_section(
        text("api_auth_security", lang),
        findings,
        {"api", "auth", "jwt", "cors", "idor", "rate_limit"},
    )
    linux_section = _linux_section(
        result.get("linux_scan", {}),
        result.get("linux_findings", []),
    )
    docker_section = _docker_section(
        result.get("docker_scan", {}),
        result.get("docker_findings", []),
    )
    service_rows = "\n".join(
        _service_row(item)
        for item in result.get("version_detection", {}).get("items", [])
    )
    service_section = _service_section(service_rows, result.get("service_findings", []))
    cve_rows = "\n".join(
        _cve_row(item) for item in result.get("cve_lookup", {}).get("items", [])
    )
    cve_section = _cve_section(
        cve_rows,
        result.get("cve_findings", []),
        result.get("cve_lookup", {}),
    )
    ai_report = generate_llm_report(
        LLMReportRequest(rule_based_result=result, language=lang)
    )
    ai_section = render_ai_report_section(ai_report, lang)
    header_section = _render_header(result, lang)
    html = f"""<!doctype html>
<html lang="{escape(lang)}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(text("title", lang))}</title>
  <style>
    :root {{ --bg: #eef3f8; --ink: #17202a; --muted: #607089; --line: #d8dee9; --panel: #ffffff; --navy: #14213d; --teal: #0f766e; --red: #b91c1c; --orange: #b45309; --blue: #2563eb; --slate: #475569; }}
    * {{ box-sizing: border-box; }}
    body {{ font-family: Arial, sans-serif; margin: 0; color: var(--ink); background: var(--bg); }}
    header {{ background: linear-gradient(135deg, #14213d 0%, #0f766e 100%); color: white; padding: 30px 38px; }}
    main {{ padding: 28px 36px; max-width: 1320px; margin: 0 auto; }}
    h1, h2, h3 {{ letter-spacing: 0; }}
    h2 {{ margin-top: 0; }}
    h3 {{ margin: 18px 0 8px; }}
    table {{ border-collapse: collapse; width: 100%; background: white; margin-top: 10px; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 10px; text-align: left; vertical-align: top; font-size: 14px; }}
    th {{ background: #edf2f7; color: #243447; }}
    .hero {{ display: flex; align-items: center; justify-content: space-between; gap: 24px; flex-wrap: wrap; }}
    .score-wrap {{ display: grid; grid-template-columns: 132px minmax(140px, 1fr); gap: 18px; align-items: center; }}
    .gauge {{ width: 132px; aspect-ratio: 1; border-radius: 50%; display: grid; place-items: center; background: conic-gradient(#22c55e calc(var(--score) * 1%), rgba(255,255,255,.22) 0); }}
    .gauge-inner {{ width: 94px; aspect-ratio: 1; border-radius: 50%; display: grid; place-items: center; background: #ffffff; color: #14213d; font-size: 30px; font-weight: 800; }}
    .score {{ display: inline-block; min-width: 76px; padding: 10px 14px; border-radius: 6px; font-size: 26px; font-weight: bold; }}
    .score.good {{ background: #d1fae5; color: #065f46; }}
    .score.warn {{ background: #fef3c7; color: #92400e; }}
    .score.bad {{ background: #fee2e2; color: #991b1b; }}
    .badge {{ display: inline-block; padding: 3px 7px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
    .pass {{ background: #dcfce7; color: #166534; }}
    .fail {{ background: #fee2e2; color: #991b1b; }}
    .warning {{ background: #fef3c7; color: #92400e; }}
    .meta {{ color: #dbeafe; margin-top: 8px; }}
    .section {{ margin-bottom: 24px; background: white; border: 1px solid var(--line); border-radius: 8px; padding: 18px; box-shadow: 0 10px 24px rgba(20,33,61,.06); }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }}
    .card {{ background: #f8fafc; border: 1px solid var(--line); border-radius: 8px; padding: 14px; }}
    .card strong {{ display: block; font-size: 22px; margin-top: 6px; }}
    .severity-card {{ border-left: 6px solid var(--slate); }}
    .severity-card.critical {{ border-left-color: #7f1d1d; background: #fff1f2; }}
    .severity-card.high {{ border-left-color: #b91c1c; background: #fef2f2; }}
    .severity-card.medium {{ border-left-color: #b45309; background: #fff7ed; }}
    .severity-card.low {{ border-left-color: #2563eb; background: #eff6ff; }}
    .severity-card.informational {{ border-left-color: #475569; background: #f8fafc; }}
    .muted {{ color: var(--muted); }}
    .subtle {{ font-size: 12px; color: var(--muted); }}
    .risk-critical {{ color: #7f1d1d; font-weight: bold; }}
    .risk-high {{ color: #991b1b; font-weight: bold; }}
    .risk-medium {{ color: #92400e; font-weight: bold; }}
    .risk-low {{ color: #1d4ed8; font-weight: bold; }}
    .risk-informational {{ color: #475569; font-weight: bold; }}
  </style>
</head>
<body>
  {header_section}
  <main>
    {executive_section}
    {severity_section}
    {top_risks_section}
    {finding_sections}
    {web_section}
    {api_section}
    <section class="section">
      <h2>{escape(text("service_version", lang))}</h2>
      {service_section}
    </section>
    {cve_section}
    {linux_section}
    {docker_section}
    {_recheck_section(result)}
    <section class="section">
    <h2>{escape(text("all_findings", lang))}</h2>
    <table>
      <thead>
        <tr>
          <th>Status</th>
          <th>Severity</th>
          <th>Category</th>
          <th>OWASP</th>
          <th>Finding</th>
          <th>Interpretation</th>
          <th>Evidence</th>
          <th>Recommendation</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    </section>
    {ai_section}
  </main>
</body>
</html>
"""
    output.write_text(html, encoding="utf-8")
    return output


def _render_header(result: dict[str, Any], language: str) -> str:
    return f"""
  <header>
    <div class="hero">
      <div>
        <h1>{escape(text("title", language))}</h1>
        <div class="meta">{escape(text("target", language))}: {escape(str(result.get("target", "")))} | {escape(text("generated", language))}: {escape(str(result.get("generated_at", "")))} | {escape(text("language", language))}: {escape(language)}</div>
      </div>
      <div class="score-wrap">
        {render_score_gauge(result)}
        <div><div class="score {score_class(result.get("score", 0))}">{escape(str(result.get("grade", "N/A")))}</div><div class="meta">{escape(text("before_after_ready", language))}</div></div>
      </div>
    </div>
  </header>"""


def render_score_gauge(result: dict[str, Any]) -> str:
    score = escape(str(result.get("score", 0)))
    label = escape(str(result.get("score", "N/A")))
    return f'<div class="gauge" style="--score: {score}"><div class="gauge-inner">{label}</div></div>'


def _finding_row(finding: dict[str, Any]) -> str:
    status = escape(str(finding.get("status", "WARNING")))
    severity = str(finding.get("severity", finding.get("risk", "")))
    language = finding.get("language")
    return f"""
        <tr>
          <td><span class="badge {status_class(status)}">{status}</span></td>
          <td><span class="risk-{escape(severity)}">{escape(str(finding.get("severity_label") or severity_label(severity, language)))}</span></td>
          <td>{escape(str(finding.get("category", "")))}</td>
          <td>{escape(str(finding.get("owasp_category", "")))}</td>
          <td>{escape(str(finding.get("title", "")))}</td>
          <td>{escape(_shorten(str(finding.get("interpretation", finding.get("description", ""))), 180))}</td>
          <td>{escape(str(finding.get("evidence", "")))}</td>
          <td>{escape(_shorten(str(finding.get("recommendation", "")), 180))}</td>
        </tr>"""


def _executive_section(result: dict[str, Any], summary: dict[str, Any]) -> str:
    score = result.get("score", "N/A")
    grade = result.get("grade", "N/A")
    lang = result.get("language")
    return f"""
    <section class="section">
      <h2>{escape(text("executive_summary", lang))}</h2>
      <div class="grid">
        <div class="card">{escape(text("security_score", lang))}<strong>{escape(str(score))}</strong></div>
        <div class="card">{escape(text("grade", lang))}<strong>{escape(str(grade))}</strong></div>
        <div class="card">{escape(text("findings", lang))}<strong>{escape(str(summary.get("total", 0)))}</strong></div>
        <div class="card">{escape(text("effective_findings", lang))}<strong>{escape(str(summary.get("effective_total", 0)))}</strong></div>
      </div>
      <p class="muted">{escape(text("target", lang))}: {escape(str(result.get("target", "")))} | {escape(text("generated", lang))}: {escape(str(result.get("generated_at", "")))}</p>
    </section>"""


def _severity_section(summary: dict[str, Any]) -> str:
    return f"""
    <section class="section">
      <h2>Findings Summary by Severity</h2>
      {render_severity_cards(summary)}
    </section>"""


def render_severity_cards(summary: dict[str, Any]) -> str:
    severities = ("critical", "high", "medium", "low", "informational")
    cards = "\n".join(
        f'<div class="card severity-card {severity}">{severity.title()}<strong class="risk-{severity}">{escape(str(summary.get(severity, 0)))}</strong></div>'
        for severity in severities
    )
    return f'<div class="grid">{cards}</div>'


def _top_risks_section(top_risks: list[dict[str, Any]]) -> str:
    if not top_risks:
        rows = """
        <tr>
          <td colspan="4">No high-priority risks were identified.</td>
        </tr>"""
    else:
        rows = "\n".join(
            f"""
        <tr>
          <td><span class="risk-{escape(str(risk.get('severity', 'informational')))}">{escape(str(risk.get('severity_label', risk.get('severity', 'informational'))))}</span></td>
          <td>{escape(str(risk.get('category', '')))}</td>
          <td>{escape(str(risk.get('owasp_category', '')))}</td>
          <td>{escape(str(risk.get('title', '')))}</td>
          <td>{escape(_shorten(str(risk.get('evidence', '')), 180))}</td>
        </tr>"""
            for risk in top_risks
        )
    return f"""
    <section class="section">
      <h2>Top Risks</h2>
      <table>
        <thead><tr><th>Severity</th><th>Category</th><th>OWASP</th><th>Finding</th><th>Evidence</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </section>"""


def _category_section(title: str, findings: list[dict[str, Any]], categories: set[str]) -> str:
    scoped = [finding for finding in findings if finding.get("category") in categories]
    if not scoped:
        rows = """
        <tr>
          <td colspan="5">No findings available for this section.</td>
        </tr>"""
    else:
        rows = "\n".join(
            f"""
        <tr>
          <td><span class="badge {status_class(str(finding.get('status', 'WARNING')))}">{escape(str(finding.get('status', 'WARNING')))}</span></td>
          <td><span class="risk-{escape(str(finding.get('severity', 'informational')))}">{escape(str(finding.get('severity_label', finding.get('severity', 'informational'))))}</span></td>
          <td>{escape(str(finding.get('owasp_category', '')))}</td>
          <td>{escape(str(finding.get('title', '')))}</td>
          <td>{escape(_shorten(str(finding.get('evidence', '')), 220))}</td>
        </tr>"""
            for finding in scoped[:12]
        )
    return f"""
    <section class="section">
      <h2>{escape(title)}</h2>
      <table>
        <thead><tr><th>Status</th><th>Severity</th><th>OWASP</th><th>Finding</th><th>Evidence</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </section>"""


def render_findings_sections(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return ""
    by_category = _count_by(findings, "category")
    by_owasp = _count_by(findings, "owasp_category")
    category_cards = "".join(
        f'<div class="card">{escape(str(name))}<strong>{escape(str(count))}</strong></div>'
        for name, count in sorted(by_category.items())
    )
    owasp_rows = "".join(
        f"<tr><td>{escape(str(name))}</td><td>{escape(str(count))}</td></tr>"
        for name, count in sorted(by_owasp.items())
    )
    return f"""
    <section class="section">
      <h2>Findings by Category and OWASP</h2>
      <div class="grid">{category_cards}</div>
      <table>
        <thead><tr><th>OWASP Top 10 Category</th><th>Findings</th></tr></thead>
        <tbody>{owasp_rows}</tbody>
      </table>
    </section>"""


def _count_by(findings: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        value = str(finding.get(key) or "Unmapped")
        counts[value] = counts.get(value, 0) + 1
    return counts


def render_ai_report_section(ai_report: dict[str, Any], language: str) -> str:
    notice_text = AI_REPORT_NOTICE
    if language != "en":
        notice_text = (
            f"{AI_REPORT_NOTICE} 탐지는 rule-based engine이 수행했으며, "
            "LLM은 결과를 요약하고 설명만 합니다."
        )
    if ai_report.get("content"):
        body = _render_ai_text(str(ai_report.get("content", "")))
        status = f"Model: {escape(str(ai_report.get('model', '')))}"
    else:
        error = ai_report.get("error") or "Ollama is not configured or did not return content."
        fallback = (
            "AI report is unavailable. The rule-based JSON and HTML report were generated normally."
            if language == "en"
            else "AI 리포트를 생성할 수 없습니다. rule-based JSON/HTML 리포트는 정상 생성되었습니다."
        )
        body = (
            f"<p>{escape(fallback)}</p>"
            f'<p class="subtle">{escape(str(error))}</p>'
        )
        status = f"Model: {escape(str(ai_report.get('model', '')))} | Fallback"
    return f"""
    <section class="section">
      <h2>AI Report</h2>
      <p class="muted">{escape(notice_text)}</p>
      <p class="subtle">{status}</p>
      <div>{body}</div>
    </section>"""


def _render_ai_text(content: str) -> str:
    blocks = []
    for raw_block in content.replace("\r\n", "\n").split("\n\n"):
        block = raw_block.strip()
        if not block:
            continue
        if block.startswith("#"):
            heading = block.lstrip("#").strip()
            blocks.append(f"<h3>{escape(heading)}</h3>")
        else:
            blocks.append(f"<p>{escape(block).replace(chr(10), '<br>')}</p>")
    return "\n".join(blocks) if blocks else "<p>No AI content returned.</p>"


def _linux_section(linux_scan: dict[str, Any], linux_findings: list[dict[str, Any]]) -> str:
    status = linux_scan.get("status", "unknown")
    environment = linux_scan.get("environment", {})
    system_info = linux_scan.get("system_info", {})
    ssh = linux_scan.get("ssh_config", {})
    firewall = linux_scan.get("firewall", {})
    file_permissions = linux_scan.get("file_permissions", {})
    accounts = linux_scan.get("accounts", {})
    severity_summary = ", ".join(
        f"{finding.get('severity', finding.get('risk'))}: {finding.get('title')}" for finding in linux_findings[:6]
    ) or "No Linux findings available."
    evidence = "; ".join(linux_scan.get("evidence", [])) or linux_scan.get("reason", "")
    if status == "skipped":
        return f"""
    <section class="section">
      <h2>Linux Security</h2>
      <p>Linux checks skipped: {escape(evidence)}</p>
      <table>
        <tbody>
          <tr><th>Status</th><td>{escape(str(status))}</td></tr>
          <tr><th>Platform</th><td>{escape(str(environment.get("platform", "unknown")))}</td></tr>
          <tr><th>Findings</th><td>{escape(severity_summary)}</td></tr>
        </tbody>
      </table>
    </section>"""
    return f"""
    <section class="section">
      <h2>Linux Security</h2>
      <p>{escape(severity_summary)}</p>
      <table>
        <tbody>
          <tr><th>Status</th><td>{escape(str(status))}</td></tr>
          <tr><th>OS</th><td>{escape(str(system_info.get("os_name", "unknown")))} {escape(str(system_info.get("os_version", "")))}</td></tr>
          <tr><th>Kernel</th><td>{escape(str(system_info.get("kernel_version", "unknown")))}</td></tr>
          <tr><th>Hostname</th><td>{escape(str(system_info.get("hostname", "unknown")))}</td></tr>
          <tr><th>User</th><td>{escape(str(system_info.get("current_user", "unknown")))}; root={escape(str(system_info.get("is_root", "unknown")))}</td></tr>
          <tr><th>SSH</th><td>{escape(_summarize_ssh(ssh))}</td></tr>
          <tr><th>Firewall</th><td>{escape(str(firewall.get("evidence", "unknown")))}</td></tr>
          <tr><th>File Permissions</th><td>{escape(_summarize_file_permissions(file_permissions))}</td></tr>
          <tr><th>Accounts</th><td>{escape(_summarize_accounts(accounts))}</td></tr>
        </tbody>
      </table>
    </section>"""


def _summarize_ssh(ssh: dict[str, Any]) -> str:
    if not ssh.get("readable"):
        return ssh.get("evidence", "sshd_config not readable.")
    settings = ssh.get("settings", {})
    keys = ["PermitRootLogin", "PasswordAuthentication", "PubkeyAuthentication", "Port", "MaxAuthTries", "X11Forwarding", "LoginGraceTime"]
    return "; ".join(f"{key}={settings.get(key)}" for key in keys)


def _summarize_file_permissions(file_permissions: dict[str, Any]) -> str:
    tmp = file_permissions.get("tmp_directories", [])
    passwd = file_permissions.get("passwd", {})
    shadow = file_permissions.get("shadow", {})
    unexpected = file_permissions.get("unexpected_suid_files", [])
    return f"tmp={len(tmp)} checked; passwd={passwd.get('mode')}; shadow={shadow.get('mode')}; unexpected_suid={len(unexpected)}"


def _summarize_accounts(accounts: dict[str, Any]) -> str:
    return (
        f"uid0={accounts.get('uid0_accounts', [])}; "
        f"interactive_system={len(accounts.get('interactive_system_accounts', []))}; "
        f"passwordless_sudo={len(accounts.get('passwordless_sudo', []))}"
    )


def _docker_section(docker_scan: dict[str, Any], docker_findings: list[dict[str, Any]]) -> str:
    status = docker_scan.get("status", "unknown")
    severity_summary = ", ".join(
        f"{finding.get('severity', finding.get('risk'))}: {finding.get('title')}" for finding in docker_findings[:6]
    ) or "No Docker findings available."
    evidence = "; ".join(docker_scan.get("evidence", [])) or docker_scan.get("reason", "")
    if status == "skipped":
        return f"""
    <section class="section">
      <h2>Docker Security</h2>
      <p>Docker checks skipped: {escape(evidence)}</p>
      <table>
        <tbody>
          <tr><th>Status</th><td>{escape(str(status))}</td></tr>
          <tr><th>Reason</th><td>{escape(str(docker_scan.get("reason", evidence)))}</td></tr>
          <tr><th>Findings</th><td>{escape(severity_summary)}</td></tr>
        </tbody>
      </table>
    </section>"""
    container_rows = "\n".join(_docker_container_row(container) for container in docker_scan.get("containers", []))
    if not container_rows:
        container_rows = """
        <tr>
          <td colspan="7">No running Docker containers observed.</td>
        </tr>"""
    return f"""
    <section class="section">
      <h2>Docker Security</h2>
      <p>{escape(severity_summary)}</p>
      <table>
        <tbody>
          <tr><th>Status</th><td>{escape(str(status))}</td></tr>
          <tr><th>Containers</th><td>{escape(str(len(docker_scan.get("containers", []))))}</td></tr>
          <tr><th>Images</th><td>{escape(_summarize_images(docker_scan.get("images", [])))}</td></tr>
          <tr><th>Evidence</th><td>{escape(evidence)}</td></tr>
        </tbody>
      </table>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Image</th>
            <th>User</th>
            <th>Privileged</th>
            <th>Network</th>
            <th>Ports</th>
            <th>Secrets / Mounts</th>
          </tr>
        </thead>
        <tbody>{container_rows}</tbody>
      </table>
    </section>"""


def _docker_container_row(container: dict[str, Any]) -> str:
    ports = ", ".join(
        f"{port.get('host_ip') or '*'}:{port.get('host_port')}->{port.get('container_port')}"
        for port in container.get("ports", [])
    ) or "none"
    secrets_mounts = f"secret_keys={len(container.get('secret_like_env_keys', []))}; mounts={len(container.get('mounts', []))}"
    return f"""
        <tr>
          <td>{escape(str(container.get("name", "")))}</td>
          <td>{escape(str(container.get("image", "")))}</td>
          <td>{escape(str(container.get("user") or "root/default"))}</td>
          <td>{escape(str(container.get("privileged", False)))}</td>
          <td>{escape(str(container.get("network_mode", "")))}</td>
          <td>{escape(ports)}</td>
          <td>{escape(secrets_mounts)}</td>
        </tr>"""


def _summarize_images(images: list[dict[str, Any]]) -> str:
    if not images:
        return "none"
    return ", ".join(f"{image.get('image')} tag={image.get('tag')} digest={image.get('digest_pinned')}" for image in images[:8])


def _service_section(service_rows: str, service_findings: list[dict[str, Any]]) -> str:
    finding_summary = ", ".join(
        f"{finding.get('severity', finding.get('risk'))}: {finding.get('title')}" for finding in service_findings
    )
    if not finding_summary:
        finding_summary = "No service findings available."
    if not service_rows:
        service_rows = """
        <tr>
          <td colspan="6">No service/version items available.</td>
        </tr>"""
    return f"""
    <section class="section">
      <h2>Service Detection</h2>
      <p>{escape(finding_summary)}</p>
      <table>
        <thead>
          <tr>
            <th>Port</th>
            <th>Protocol</th>
            <th>Service</th>
            <th>Version</th>
            <th>Confidence</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>{service_rows}</tbody>
      </table>
    </section>"""


def _service_row(item: dict[str, Any]) -> str:
    normalized = item.get("normalized_service", {})
    version = item.get("version") or normalized.get("version") or "unknown"
    product = normalized.get("product")
    if product and product != "unknown" and version != "unknown":
        version = f"{product} {version}"
    return f"""
        <tr>
          <td>{escape(str(item.get("port", "")))}</td>
          <td>{escape(str(item.get("protocol", "")))}</td>
          <td>{escape(str(item.get("service", "")))}</td>
          <td>{escape(str(version))}</td>
          <td>{escape(str(item.get("confidence", "")))}</td>
          <td>{escape(str(item.get("evidence", "")))}</td>
        </tr>"""


def _cve_section(cve_rows: str, cve_findings: list[dict[str, Any]], cve_lookup: dict[str, Any]) -> str:
    finding_summary = ", ".join(
        f"{finding.get('severity', finding.get('risk'))}: {finding.get('title')}" for finding in cve_findings[:5]
    )
    if not finding_summary:
        finding_summary = cve_lookup.get("note") or "No CVE findings available."
    if not cve_rows:
        errors = "; ".join(cve_lookup.get("errors", []))
        message = errors or "No CVE items available."
        cve_rows = f"""
        <tr>
          <td colspan="7">{escape(message)}</td>
        </tr>"""
    return f"""
    <section class="section">
      <h2>CVE / CVSS</h2>
      <p>{escape(finding_summary)}</p>
      <table>
        <thead>
          <tr>
            <th>CVE ID</th>
            <th>CVSS</th>
            <th>Severity</th>
            <th>Product / Version</th>
            <th>Confidence</th>
            <th>Description</th>
            <th>References</th>
          </tr>
        </thead>
        <tbody>{cve_rows}</tbody>
      </table>
    </section>"""


def _cve_row(item: dict[str, Any]) -> str:
    references = item.get("references", [])
    reference_html = _reference_html(references)
    description = str(item.get("description", ""))
    if len(description) > 220:
        description = description[:217] + "..."
    return f"""
        <tr>
          <td>{escape(str(item.get("cve_id", "")))}</td>
          <td>{escape(str(item.get("cvss_score", "unknown")))} ({escape(str(item.get("cvss_version", "unknown")))})</td>
          <td>{escape(str(item.get("severity", "unknown")))}</td>
          <td>{escape(str(item.get("matched_product", "unknown")))} {escape(str(item.get("matched_version", "unknown")))}</td>
          <td>{escape(str(item.get("confidence", "low")))}</td>
          <td>{escape(description)}</td>
          <td>{reference_html}</td>
        </tr>"""


def _reference_html(references: list[str]) -> str:
    if not references:
        return "0"
    first = escape(references[0])
    return f'<a href="{first}">{len(references)} reference(s)</a>'


def _recheck_section(result: dict[str, Any]) -> str:
    if "changes" not in result:
        return ""
    severity_delta = result.get("severity_delta", {})
    summary = result.get("summary", {})
    return f"""
    <section class="section">
      <h2>Recheck Summary</h2>
      <div class="grid">
        <div class="card">Before<strong>{escape(str(result.get("before_score", "N/A")))} / {escape(str(result.get("before_grade", "N/A")))}</strong></div>
        <div class="card">After<strong>{escape(str(result.get("after_score", "N/A")))} / {escape(str(result.get("after_grade", "N/A")))}</strong></div>
        <div class="card">Score Delta<strong>{escape(str(result.get("score_delta", "N/A")))}</strong></div>
        <div class="card">Resolved<strong>{escape(str(len(result.get("resolved_findings", []))))}</strong></div>
        <div class="card">New<strong>{escape(str(len(result.get("new_findings", []))))}</strong></div>
        <div class="card">Unchanged<strong>{escape(str(len(result.get("unchanged_findings", []))))}</strong></div>
      </div>
      <p class="muted">Severity delta: critical {escape(str(severity_delta.get("critical", 0)))}, high {escape(str(severity_delta.get("high", 0)))}, medium {escape(str(severity_delta.get("medium", 0)))}, low {escape(str(severity_delta.get("low", 0)))}. Changed: {escape(str(summary.get("changed", 0)))}.</p>
    </section>"""


def _shorten(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 3)] + "..."
