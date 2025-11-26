import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Mapping

from src.adapters import detect_provider, fetch_context, post_comment
from src.ai_analyzer import AIAnalyzer
from src.dependency_checker import evaluate_supply_chain
from src.risk_engine import evaluate_static_risks

LOG_PATH = Path("repo_guard.log")


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(LOG_PATH, mode="w"),
        ],
    )


def orchestrate(env: Mapping[str, str]) -> Dict[str, Any]:
    context = detect_provider(env)
    context_bundle = fetch_context(context)
    diff_text = context_bundle.get("diff_text", "")
    file_contexts = context_bundle.get("files", [])

    static_result = evaluate_static_risks(diff_text)
    dependency_result = evaluate_supply_chain(diff_text)

    ai_result = _run_ai(diff_text, file_contexts)
    if ai_result["score"] is None:
        ai_result["score"] = static_result["score"]
        ai_result["summary"] = (
            f"{ai_result['summary']} Defaulted to static risk score."
        )

    holistic_score = _aggregate_score(
        static_result["score"], dependency_result["score"], ai_result["score"]
    )
    status = _score_to_status(holistic_score)

    report = _build_report(
        holistic_score=holistic_score,
        status=status,
        ai_summary=ai_result["summary"],
        static_score=static_result["score"],
        dependency_score=dependency_result["score"],
        ai_score=ai_result["score"],
        findings=_merge_findings(static_result, dependency_result, ai_result),
    )

    post_comment(context, report)

    return {
        "score": holistic_score,
        "status": status,
        "report": report,
    }


def _run_ai(diff_text: str, file_contexts: List[Mapping[str, str]]) -> Dict[str, Any]:
    try:
        analyzer = AIAnalyzer()
    except ValueError as exc:
        logging.getLogger(__name__).error("AI analyzer not configured: %s", exc)
        return {"score": None, "findings": [], "summary": str(exc)}

    return analyzer.analyze_impact(diff_text, file_contexts)


def _aggregate_score(static_score: int, dependency_score: int, ai_score: int) -> int:
    weighted = (
        static_score * 0.3
        + dependency_score * 0.3
        + ai_score * 0.4
    )
    return int(round(weighted))


def _score_to_status(score: int) -> str:
    if score <= 30:
        return "🟢 SAFE"
    if score <= 60:
        return "🟡 WARNING"
    return "🔴 CRITICAL"


def _build_report(
    holistic_score: int,
    status: str,
    ai_summary: str,
    static_score: int,
    dependency_score: int,
    ai_score: int,
    findings: List[Dict[str, Any]],
) -> str:
    summary_table = (
        "| Metric | Score | Notes |\n"
        "| --- | --- | --- |\n"
        f"| Holistic | {holistic_score} ({status}) | {ai_summary} |\n"
        f"| Static Analysis | {static_score} | Secret & churn scan |\n"
        f"| Supply Chain | {dependency_score} | Dependency hygiene |\n"
        f"| AI Impact | {ai_score} | Model-assisted prediction |\n"
    )

    detail_lines = "\n".join(
        _format_finding(finding) for finding in findings
    ) or "_No issues detected._"

    return (
        "## RepoGuard Executive Summary\n"
        f"{summary_table}\n"
        "## Detailed Findings\n"
        f"{detail_lines}\n"
    )


def _merge_findings(
    static_result: Mapping[str, Any],
    dependency_result: Mapping[str, Any],
    ai_result: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for source in (static_result, dependency_result):
        for item in source.get("findings", []):
            normalized = dict(item)
            normalized.setdefault("snippet", "")
            findings.append(normalized)

    for item in ai_result.get("findings", []):
        findings.append(
            {
                "file": item.get("file", "unknown"),
                "line": item.get("line_number", 0),
                "issue": item.get("issue") or item.get("summary", "AI flagged issue."),
                "tag": "ai_insight",
                "severity": item.get("severity", "medium"),
                "snippet": item.get("snippet", ""),
                "suggested_fix": item.get("suggested_fix"),
                "confidence_score": item.get("confidence_score"),
                "summary": item.get("summary", ""),
            }
        )
    return findings


def _format_finding(finding: Mapping[str, Any]) -> str:
    file_path = finding.get("file", "unknown")
    line = finding.get("line") or finding.get("line_number") or 0
    issue = finding.get("issue", "Issue not specified.")
    severity = str(finding.get("severity", "medium")).lower()
    severity_label = severity.capitalize()
    emoji_map = {"high": "🔴", "medium": "🟠", "low": "🟢"}
    emoji = emoji_map.get(severity, "⚠️")
    snippet = (finding.get("snippet") or "").strip()
    suggestion = finding.get("suggested_fix") or finding.get("remediation") or ""
    confidence = finding.get("confidence_score")

    summary_line = f"{emoji} [{severity_label}] {issue} in {file_path}"
    details: List[str] = [
        "<details>",
        f"<summary>{summary_line}</summary>",
        "",
        f"**Issue:** {issue}",
        f"**Location:** Line {line}",
    ]

    if snippet:
        details.extend(
            [
                "**Snippet:**",
                "```python",
                snippet,
                "```",
            ]
        )

    if suggestion:
        details.append(f"**AI Suggestion:** {suggestion}")

    if confidence is not None:
        try:
            details.append(f"**Confidence:** {float(confidence):.2f}")
        except (TypeError, ValueError):
            pass

    details.append("</details>")
    return "\n".join(details)


def main() -> None:
    configure_logging()
    result = orchestrate(os.environ)
    logging.info("RepoGuard finished with score %d (%s)", result["score"], result["status"])
    if result["score"] > 80:
        raise SystemExit("Build failed: Risk score exceeded threshold.")


if __name__ == "__main__":
    main()

