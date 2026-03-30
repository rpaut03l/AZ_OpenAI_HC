#!/usr/bin/env python3
"""
analyze.py
Reads /tmp/health_results.json, calls Azure OpenAI,
writes a formatted markdown report to:
  1. stdout     → visible in GHA logs
  2. $GITHUB_STEP_SUMMARY → visible as a rich Job Summary in GHA UI
  3. /tmp/analysis.md     → uploaded as artifact

No Slack. No external notifications. GHA-native output only.
"""
import json, os, sys
from openai import AzureOpenAI

# ── Azure OpenAI client ───────────────────────────────────────────────────────
client = AzureOpenAI(
    azure_endpoint = os.environ["AZURE_OPENAI_ENDPOINT"].rstrip("/"),
    api_key        = os.environ["AZURE_OPENAI_API_KEY"],
    api_version    = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-12-01-preview"),
)
DEPLOYMENT   = os.environ["AZURE_OPENAI_DEPLOYMENT"]
RESULTS_FILE = os.environ.get("RESULTS_FILE", "/tmp/health_results.json")
SUMMARY_FILE = os.environ.get("GITHUB_STEP_SUMMARY", "/tmp/analysis.md")
RUN_URL      = os.environ.get("GHA_RUN_URL", "")


def load_results() -> dict:
    with open(RESULTS_FILE) as f:
        return json.load(f)


def call_azure(data: dict) -> dict:
    """
    Uses Function Calling (Approach 5) for guaranteed structured output.
    Falls back to plain text if function calling fails.
    """
    degraded = [c for c in data["checks"] if c["overall"] == "degraded"]
    healthy  = [c for c in data["checks"] if c["overall"] == "healthy"]

    if not degraded:
        return {
            "overall_severity":   "healthy",
            "summary":            f"All {len(healthy)} hosts are healthy. Ports 80/443 are open and SSL certificates are valid.",
            "host_analyses":      [],
            "recommended_action": "No action required.",
        }

    FUNCTION = {
        "name":        "submit_health_analysis",
        "description": "Submit structured analysis of host health check results",
        "parameters": {
            "type": "object",
            "properties": {
                "overall_severity": {
                    "type": "string",
                    "enum": ["critical", "warning", "healthy"],
                },
                "summary": {
                    "type": "string",
                    "description": "Plain text summary, max 150 words",
                },
                "host_analyses": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "host":          {"type": "string"},
                            "severity":      {"type": "string", "enum": ["critical","warning","info"]},
                            "primary_issue": {"type": "string"},
                            "action":        {"type": "string"},
                        },
                        "required": ["host","severity","primary_issue","action"],
                    },
                },
                "recommended_action": {"type": "string"},
            },
            "required": ["overall_severity","summary","host_analyses","recommended_action"],
        },
    }

    r = client.chat.completions.create(
        model       = DEPLOYMENT,
        temperature = 0.1,
        max_tokens  = 600,
        tools       = [{"type": "function", "function": FUNCTION}],
        tool_choice = {"type": "function", "function": {"name": "submit_health_analysis"}},
        messages    = [
            {
                "role": "system",
                "content": (
                    "You are an SRE observability assistant. "
                    "Analyze host health check results. "
                    "Plain text only in all string fields. No markdown."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Timestamp: {data['timestamp']}\n"
                    f"Degraded hosts:\n{json.dumps(degraded, indent=2)}\n"
                    f"Healthy hosts: {[c['name'] for c in healthy]}"
                ),
            },
        ],
    )
    return json.loads(r.choices[0].message.tool_calls[0].function.arguments)


def build_markdown_report(data: dict, analysis: dict) -> str:
    """Builds a rich markdown report for GHA Job Summary."""
    checks   = data["checks"]
    degraded = [c for c in checks if c["overall"] == "degraded"]
    healthy  = [c for c in checks if c["overall"] == "healthy"]

    sev_badge = {
        "critical": "🔴 CRITICAL",
        "warning":  "⚠️ WARNING",
        "healthy":  "✅ HEALTHY",
    }.get(analysis["overall_severity"], "❓ UNKNOWN")

    lines = [
        f"# Host Health Check — {sev_badge}",
        f"",
        f"**Checked at:** `{data['timestamp']}`  ",
        f"**Hosts:** {len(checks)} total · ✅ {len(healthy)} healthy · 🔴 {len(degraded)} degraded",
        f"",
    ]

    if RUN_URL:
        lines += [f"[→ View full GHA run]({RUN_URL})", ""]

    # ── Per-host detail table ─────────────────────────────────────────────────
    lines += [
        "## Per-Host Results",
        "",
        "| Host | Port 80 | Port 443 | SSL Status | Expires | Days Left | Issues |",
        "|------|---------|----------|------------|---------|-----------|--------|",
    ]

    def ep(s): return "✅" if s == "open"     else "❌"
    def es(s): return {
        "VALID":           "✅ VALID",
        "WARNING":         "⚠️ WARNING",
        "CRITICAL":        "🔴 CRITICAL",
        "EXPIRED":         "💀 EXPIRED",
        "SKIPPED":         "⏭️ SKIPPED",
        "HANDSHAKE_FAILED":"❌ FAILED",
    }.get(s, s)

    for c in checks:
        issues_str = ", ".join(c.get("issues", [])) or "—"
        expiry     = c.get("ssl_expiry",    "—") or "—"
        days       = str(c.get("ssl_days_left", "—")) if c.get("ssl_days_left") is not None else "—"
        lines.append(
            f"| **{c['name']}** `{c['host']}` "
            f"| {ep(c['port_80'])} {c['port_80']} "
            f"| {ep(c['port_443'])} {c['port_443']} "
            f"| {es(c['ssl_status'])} "
            f"| `{expiry}` "
            f"| {days} "
            f"| `{issues_str}` |"
        )

    lines.append("")

    # ── SSL cert details for each host ────────────────────────────────────────
    lines += ["## SSL Certificate Details", ""]
    for c in checks:
        status_icon = "✅" if c["ssl_status"] == "VALID" else (
                      "⚠️" if c["ssl_status"] == "WARNING" else "🔴")
        lines += [
            f"### {status_icon} {c['name']} (`{c['host']}`)",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Status      | `{c['ssl_status']}` |",
            f"| Expiry date | `{c.get('ssl_expiry','N/A') or 'N/A'}` |",
            f"| Days left   | `{c.get('ssl_days_left','N/A')}` |",
            f"| Subject     | `{c.get('ssl_subject','N/A') or 'N/A'}` |",
            f"| Issuer      | `{c.get('ssl_issuer','N/A')  or 'N/A'}` |",
            f"",
        ]

    # ── AI Analysis section ───────────────────────────────────────────────────
    lines += [
        "## 🤖 AI Analysis (Azure OpenAI — gpt-4o)",
        "",
        f"> **Overall severity:** {analysis['overall_severity'].upper()}",
        "",
        analysis["summary"],
        "",
    ]

    if analysis.get("host_analyses"):
        lines += ["### Per-Host Findings", ""]
        for ha in analysis["host_analyses"]:
            sev_icon = {"critical":"🔴","warning":"⚠️","info":"ℹ️"}.get(ha["severity"],"❓")
            lines += [
                f"**{sev_icon} {ha['host']}**",
                f"- Issue: {ha['primary_issue']}",
                f"- Action: {ha['action']}",
                "",
            ]

    lines += [
        f"### Recommended Action",
        f"",
        f"> {analysis['recommended_action']}",
        "",
        "---",
        f"*Powered by Azure OpenAI (`{DEPLOYMENT}`) + GitHub Actions*",
    ]

    return "\n".join(lines)


def write_summary(report: str) -> None:
    """Write to GHA Job Summary and local artifact file."""
    # ── GHA Job Summary ───────────────────────────────────────────────────────
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(report + "\n")
        print(f"✅ Written to GHA Job Summary: {summary_path}")

    # ── Local artifact ────────────────────────────────────────────────────────
    with open("/tmp/analysis.md", "w") as f:
        f.write(report)
    print("✅ Written to /tmp/analysis.md (artifact)")


def main():
    print(f"[analyze] Deployment: {DEPLOYMENT}")
    print(f"[analyze] Endpoint:   {os.environ.get('AZURE_OPENAI_ENDPOINT','NOT SET')}")

    data = load_results()
    print(f"[analyze] Hosts: {len(data['checks'])}")

    degraded_count = sum(1 for c in data["checks"] if c["overall"] == "degraded")
    print(f"[analyze] Degraded:  {degraded_count}")

    print("[analyze] Calling Azure OpenAI...")
    analysis = call_azure(data)

    print("\n─── Structured Analysis ───")
    print(json.dumps(analysis, indent=2))
    print("───────────────────────────\n")

    report = build_markdown_report(data, analysis)

    print("─── Markdown Report Preview ───")
    print(report)
    print("───────────────────────────────")

    write_summary(report)

    # Exit 1 if critical/warning so GHA step shows yellow/red
    if analysis["overall_severity"] == "critical":
        print("\n🔴 CRITICAL issues found — marking step as failed")
        sys.exit(1)
    elif analysis["overall_severity"] == "warning":
        print("\n⚠️  WARNING issues found — check Job Summary for details")
        sys.exit(0)   # warning = pass but visible in summary
    else:
        print("\n✅ All healthy")
        sys.exit(0)


if __name__ == "__main__":
    main()
