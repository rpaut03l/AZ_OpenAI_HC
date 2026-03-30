#!/usr/bin/env python3
"""
analyze.py — Azure OpenAI analysis with LangSmith observability.

LangSmith traces every run including:
  - Full prompt sent to Azure OpenAI
  - Full response received
  - Token usage (input/output/total)
  - Latency per call
  - Run metadata (host names, severity, GHA run URL)
  - Errors with full stack trace if any call fails

All traces visible at: https://smith.langchain.com
Project: openai-health-check  (auto-created on first run)

Required env vars (GitHub secrets):
  AZURE_OPENAI_ENDPOINT
  AZURE_OPENAI_API_KEY
  AZURE_OPENAI_DEPLOYMENT
  AZURE_OPENAI_API_VERSION
  LANGSMITH_API_KEY           ← new

Optional env vars:
  LANGSMITH_PROJECT           ← defaults to "openai-health-check"
  LANGSMITH_ENDPOINT          ← defaults to https://api.smith.langchain.com
                                 use https://eu.api.smith.langchain.com for EU
"""

import json, os, sys, time
from datetime import datetime, timezone

# ── LangSmith — must be set BEFORE importing openai/langchain ────────────────
# These three env vars activate tracing automatically for all LLM calls
os.environ["LANGSMITH_TRACING"]  = "true"
os.environ["LANGSMITH_ENDPOINT"] = os.environ.get(
    "LANGSMITH_ENDPOINT", "https://api.smith.langchain.com"
)
os.environ["LANGSMITH_API_KEY"]  = os.environ["LANGSMITH_API_KEY"]
os.environ["LANGSMITH_PROJECT"]  = os.environ.get(
    "LANGSMITH_PROJECT", "openai-health-check"
)

# ── LangSmith SDK ─────────────────────────────────────────────────────────────
from langsmith import Client, traceable
from langsmith.run_helpers import get_current_run_tree

# ── Azure OpenAI via LangChain (auto-traced by LangSmith) ────────────────────
from langchain_openai              import AzureChatOpenAI
from langchain_core.prompts        import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

# ── Config ────────────────────────────────────────────────────────────────────
DEPLOYMENT   = os.environ["AZURE_OPENAI_DEPLOYMENT"]
RESULTS_FILE = os.environ.get("RESULTS_FILE", "/tmp/health_results.json")
RUN_URL      = os.environ.get("GHA_RUN_URL", "")
GHA_RUN_ID   = os.environ.get("GITHUB_RUN_ID", "local")
REPOSITORY   = os.environ.get("GITHUB_REPOSITORY", "rpaut03/AZ_OpenAI_HC")
DRY_RUN      = os.environ.get("DRY_RUN", "false").lower() == "true"

# ── LangSmith client (for adding feedback + metadata) ────────────────────────
ls_client = Client()

# ── Azure OpenAI LangChain client ─────────────────────────────────────────────
llm = AzureChatOpenAI(
    azure_endpoint   = os.environ["AZURE_OPENAI_ENDPOINT"].rstrip("/"),
    api_key          = os.environ["AZURE_OPENAI_API_KEY"],
    azure_deployment = DEPLOYMENT,
    api_version      = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-12-01-preview"),
    temperature      = 0.1,
    max_tokens       = 600,
    # LangSmith metadata — appears on every trace for this model
    model_kwargs     = {
        "extra_headers": {
            "X-Source": "gha-health-check",
            "X-Repo":   REPOSITORY,
        }
    },
)


# ─────────────────────────────────────────────────────────────────────────────
# Traced functions — @traceable creates a named span in LangSmith for each
# ─────────────────────────────────────────────────────────────────────────────

@traceable(
    name       = "load_probe_results",
    run_type   = "tool",
    tags       = ["io", "probe"],
    metadata   = {"source": "host_health_check.sh", "repo": REPOSITORY},
)
def load_results() -> dict:
    """Load and validate JSON results from the probe script."""
    with open(RESULTS_FILE) as f:
        data = json.load(f)

    # Attach probe metadata to current LangSmith span
    run = get_current_run_tree()
    if run:
        run.add_metadata({
            "hosts_checked": [c["host"] for c in data["checks"]],
            "total_hosts":   len(data["checks"]),
            "timestamp":     data["timestamp"],
            "results_file":  RESULTS_FILE,
        })

    return data


@traceable(
    name     = "analyze_host_health",
    run_type = "chain",
    tags     = ["azure-openai", "analysis", "sre"],
    metadata = {
        "deployment":  DEPLOYMENT,
        "gha_run_id":  GHA_RUN_ID,
        "repository":  REPOSITORY,
        "run_url":     RUN_URL,
    },
)
def analyze_with_azure(data: dict) -> dict:
    """
    Main analysis function — calls Azure OpenAI with full LangSmith tracing.

    LangSmith captures:
    - The full prompt template + filled values
    - The raw model response
    - Token counts (prompt_tokens, completion_tokens, total_tokens)
    - Latency (ms)
    - Model name and deployment
    - Any errors or retries
    """
    degraded = [c for c in data["checks"] if c["overall"] == "degraded"]
    healthy  = [c for c in data["checks"] if c["overall"] == "healthy"]

    run = get_current_run_tree()

    # ── Fast path: nothing degraded ───────────────────────────────────────────
    if not degraded:
        result = {
            "overall_severity":   "healthy",
            "summary":            (
                f"All {len(healthy)} hosts healthy. "
                "Ports 80/443 open, SSL certificates valid."
            ),
            "host_analyses":      [],
            "recommended_action": "No action required.",
            "skipped_llm_call":   True,
        }
        if run:
            run.add_metadata({"llm_called": False, "reason": "all_healthy"})
        return result

    # ── Build structured analysis prompt ──────────────────────────────────────
    # Using LangChain LCEL so LangSmith auto-traces the prompt + model call
    PROMPT = ChatPromptTemplate.from_messages([
        (
            "system",
            """You are an SRE observability assistant analysing host health check results.
Your response MUST be valid JSON only — no markdown, no code fences, no extra text.
Return exactly this schema:
{{
  "overall_severity": "critical" | "warning" | "healthy",
  "summary": "plain text, max 150 words",
  "host_analyses": [
    {{
      "host":          "hostname",
      "severity":      "critical" | "warning" | "info",
      "primary_issue": "one-line description",
      "action":        "recommended fix"
    }}
  ],
  "recommended_action": "single top-level action"
}}""",
        ),
        (
            "human",
            "Timestamp: {timestamp}\n\nDegraded hosts:\n{degraded_json}\n\nHealthy hosts: {healthy_names}",
        ),
    ])

    chain = PROMPT | llm | StrOutputParser()

    start_time = time.time()

    raw_response = chain.invoke(
        {
            "timestamp":     data["timestamp"],
            "degraded_json": json.dumps(degraded, indent=2),
            "healthy_names": [c["name"] for c in healthy],
        },
        # LangSmith run name for this specific invocation
        config={"run_name": f"health-analysis-{GHA_RUN_ID}"},
    )

    latency_ms = int((time.time() - start_time) * 1000)

    # ── Parse JSON response ───────────────────────────────────────────────────
    clean = raw_response.strip()
    if clean.startswith("```"):
        clean = clean.split("```")[1]
        if clean.startswith("json"):
            clean = clean[4:]
    analysis = json.loads(clean.strip())

    # ── Validate required keys ────────────────────────────────────────────────
    required = ["overall_severity", "summary", "host_analyses", "recommended_action"]
    missing  = [k for k in required if k not in analysis]
    if missing:
        raise ValueError(f"Model response missing required keys: {missing}")

    # ── Attach rich metadata to this LangSmith span ───────────────────────────
    if run:
        run.add_metadata({
            "overall_severity":  analysis["overall_severity"],
            "degraded_count":    len(degraded),
            "healthy_count":     len(healthy),
            "latency_ms":        latency_ms,
            "gha_run_url":       RUN_URL,
            "deployment":        DEPLOYMENT,
            "llm_called":        True,
        })

    return analysis


@traceable(
    name     = "create_jira_ticket",
    run_type = "tool",
    tags     = ["jira", "ticketing", "port-issue"],
)
def trace_jira_creation(port_issue_hosts: str, ticket_key: str, ticket_url: str) -> dict:
    """
    Records JIRA ticket creation event in LangSmith.
    Called AFTER the actual API call succeeds so we capture the outcome.
    """
    run = get_current_run_tree()
    if run:
        run.add_metadata({
            "ticket_key":        ticket_key,
            "ticket_url":        ticket_url,
            "affected_hosts":    port_issue_hosts,
            "action":            "jira_ticket_created",
        })
    return {
        "ticket_key": ticket_key,
        "ticket_url": ticket_url,
        "hosts":      port_issue_hosts,
    }


@traceable(
    name     = "create_servicenow_ritm",
    run_type = "tool",
    tags     = ["servicenow", "ritm", "ssl-issue"],
)
def trace_snow_creation(ssl_issue_hosts: str, ritm_number: str, ritm_url: str) -> dict:
    """
    Records ServiceNow RITM creation event in LangSmith.
    Called AFTER the actual API call succeeds.
    """
    run = get_current_run_tree()
    if run:
        run.add_metadata({
            "ritm_number":    ritm_number,
            "ritm_url":       ritm_url,
            "affected_hosts": ssl_issue_hosts,
            "action":         "snow_ritm_created",
        })
    return {
        "ritm_number": ritm_number,
        "ritm_url":    ritm_url,
        "hosts":       ssl_issue_hosts,
    }


@traceable(
    name     = "build_gha_summary",
    run_type = "tool",
    tags     = ["reporting", "gha-summary"],
)
def build_and_write_summary(data: dict, analysis: dict) -> str:
    """Builds markdown report and writes to GHA Job Summary."""
    checks   = data["checks"]
    degraded = [c for c in checks if c["overall"] == "degraded"]
    healthy  = [c for c in checks if c["overall"] == "healthy"]

    sev_badge = {
        "critical": "🔴 CRITICAL",
        "warning":  "⚠️ WARNING",
        "healthy":  "✅ HEALTHY",
    }.get(analysis["overall_severity"], "❓ UNKNOWN")

    def ep(s): return "✅" if s == "open"    else "❌"
    def es(s): return {
        "VALID":            "✅ VALID",
        "WARNING":          "⚠️ WARNING",
        "CRITICAL":         "🔴 CRITICAL",
        "EXPIRED":          "💀 EXPIRED",
        "SKIPPED":          "⏭️ SKIPPED",
        "HANDSHAKE_FAILED": "❌ FAILED",
    }.get(s, s)

    ls_project  = os.environ.get("LANGSMITH_PROJECT", "openai-health-check")
    ls_base_url = "https://smith.langchain.com"
    ls_url      = f"{ls_base_url}/o/default/projects/p/{ls_project}"

    lines = [
        f"# Host Health Check — {sev_badge}",
        f"",
        f"**Checked at:** `{data['timestamp']}`  ",
        f"**Hosts:** {len(checks)} total · ✅ {len(healthy)} healthy · 🔴 {len(degraded)} degraded",
        f"",
    ]

    if RUN_URL:
        lines += [f"[→ View GHA Run]({RUN_URL})  |  [→ View LangSmith Trace]({ls_url})", ""]

    # ── Results table ─────────────────────────────────────────────────────────
    lines += [
        "## Per-Host Results",
        "",
        "| Host | Port 80 | Port 443 | SSL | Expiry | Days Left | Issues |",
        "|------|---------|----------|-----|--------|-----------|--------|",
    ]
    for c in checks:
        issues_str = ", ".join(c.get("issues", [])) or "—"
        expiry     = c.get("ssl_expiry",    "—") or "—"
        days       = str(c.get("ssl_days_left", "—")) \
                     if c.get("ssl_days_left") is not None else "—"
        lines.append(
            f"| **{c['name']}** `{c['host']}` "
            f"| {ep(c['port_80'])} {c['port_80']} "
            f"| {ep(c['port_443'])} {c['port_443']} "
            f"| {es(c['ssl_status'])} "
            f"| `{expiry}` "
            f"| {days} "
            f"| `{issues_str}` |"
        )

    # ── SSL cert detail per host ──────────────────────────────────────────────
    lines += ["", "## SSL Certificate Details", ""]
    for c in checks:
        icon = {"VALID":"✅","WARNING":"⚠️","CRITICAL":"🔴","EXPIRED":"💀"}.get(
            c["ssl_status"], "❓"
        )
        lines += [
            f"### {icon} {c['name']} (`{c['host']}`)",
            "| Field | Value |",
            "|-------|-------|",
            f"| Status      | `{c['ssl_status']}` |",
            f"| Expiry date | `{c.get('ssl_expiry','N/A') or 'N/A'}` |",
            f"| Days left   | `{c.get('ssl_days_left','N/A')}` |",
            f"| Subject     | `{c.get('ssl_subject','N/A') or 'N/A'}` |",
            f"| Issuer      | `{c.get('ssl_issuer','N/A')  or 'N/A'}` |",
            "",
        ]

    # ── AI Analysis ───────────────────────────────────────────────────────────
    lines += [
        "## 🤖 AI Analysis (Azure OpenAI)",
        "",
        f"> **Overall severity:** `{analysis['overall_severity'].upper()}`",
        "",
        analysis["summary"],
        "",
    ]
    if analysis.get("host_analyses"):
        lines += ["### Per-Host Findings", ""]
        for ha in analysis["host_analyses"]:
            se = {"critical":"🔴","warning":"⚠️","info":"ℹ️"}.get(ha["severity"],"❓")
            lines += [
                f"**{se} {ha['host']}**",
                f"- Issue: {ha['primary_issue']}",
                f"- Action: {ha['action']}",
                "",
            ]
    lines += [
        "### Recommended Action",
        "",
        f"> {analysis['recommended_action']}",
        "",
    ]

    # ── LangSmith observability section ───────────────────────────────────────
    lines += [
        "## 📊 Observability — LangSmith",
        "",
        f"All Azure OpenAI calls from this run are traced in LangSmith.",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Project | `{ls_project}` |",
        f"| GHA Run ID | `{GHA_RUN_ID}` |",
        f"| Deployment | `{DEPLOYMENT}` |",
        f"| LangSmith UI | [Open traces]({ls_url}) |",
        "",
        "Traces include: prompt sent, response received, token usage, latency, errors.",
        "",
        "---",
        f"*Powered by Azure OpenAI `{DEPLOYMENT}` + LangSmith + GitHub Actions*",
    ]

    report = "\n".join(lines)

    # ── Write to GHA Job Summary ──────────────────────────────────────────────
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(report + "\n")

    # ── Write to artifact ─────────────────────────────────────────────────────
    with open("/tmp/analysis.md", "w") as f:
        f.write(report)

    return report


# ─────────────────────────────────────────────────────────────────────────────
# Root traceable — wraps the entire run as one top-level LangSmith trace
# ─────────────────────────────────────────────────────────────────────────────
@traceable(
    name     = "host-health-check-pipeline",
    run_type = "chain",
    tags     = ["sre", "health-check", "gha", "rohitpatel.in", "rohitpatel.ai"],
    metadata = {
        "gha_run_id":   GHA_RUN_ID,
        "repository":   REPOSITORY,
        "run_url":      RUN_URL,
        "triggered_by": os.environ.get("GITHUB_EVENT_NAME", "unknown"),
        "actor":        os.environ.get("GITHUB_ACTOR", "unknown"),
    },
)
def run_pipeline() -> dict:
    """
    Root pipeline function — entire execution is one LangSmith trace.

    Tree visible in LangSmith:
      host-health-check-pipeline
        ├── load_probe_results
        ├── analyze_host_health
        │     └── RunnableSequence (LCEL chain)
        │           ├── ChatPromptTemplate
        │           └── AzureChatOpenAI  ← token counts + latency here
        └── build_gha_summary
    """
    print(f"[pipeline] LangSmith project: {os.environ.get('LANGSMITH_PROJECT')}")
    print(f"[pipeline] Deployment:        {DEPLOYMENT}")
    print(f"[pipeline] GHA Run ID:        {GHA_RUN_ID}")

    # Step 1 — load results
    data = load_results()
    degraded_count = sum(1 for c in data["checks"] if c["overall"] == "degraded")
    print(f"[pipeline] Hosts checked:     {len(data['checks'])}")
    print(f"[pipeline] Degraded:          {degraded_count}")

    # Step 2 — Azure OpenAI analysis
    analysis = analyze_with_azure(data)
    print(f"[pipeline] Severity:          {analysis['overall_severity']}")
    print(f"\n─── Analysis ───\n{json.dumps(analysis, indent=2)}\n────────────────")

    # Step 3 — Build + write GHA summary
    build_and_write_summary(data, analysis)

    # Step 4 — Add LangSmith feedback score
    # Automatically scores each run so you can track quality over time
    # in LangSmith's dashboard (Feedback tab)
    try:
        score = 1.0 if analysis["overall_severity"] == "healthy" else 0.0
        run   = get_current_run_tree()
        if run and run.id:
            ls_client.create_feedback(
                run_id    = run.id,
                key       = "host_health_score",
                score     = score,
                comment   = (
                    f"overall_severity={analysis['overall_severity']} "
                    f"degraded={degraded_count}/{len(data['checks'])}"
                ),
            )
            print(f"[langsmith] Feedback score logged: {score}")
    except Exception as e:
        print(f"[langsmith] Feedback logging skipped: {e}")

    # Step 5 — Flush all pending traces before GHA runner exits
    # Critical for short-lived CI environments
    try:
        from langsmith.run_helpers import wait_for_all_tracers
        wait_for_all_tracers()
        print("[langsmith] All traces flushed ✅")
    except Exception as e:
        print(f"[langsmith] Flush warning: {e}")

    return analysis


def main():
    analysis = run_pipeline()

    severity = analysis["overall_severity"]
    if severity == "critical":
        print("\n🔴 CRITICAL — marking GHA step as failed")
        sys.exit(1)
    elif severity == "warning":
        print("\n⚠️  WARNING — check Job Summary and LangSmith for details")
        sys.exit(0)
    else:
        print("\n✅ All healthy — no action needed")
        sys.exit(0)


if __name__ == "__main__":
    main()
