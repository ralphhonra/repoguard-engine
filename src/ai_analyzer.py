import json
import logging
import os
from typing import Any, Dict, List, Mapping

from openai import OpenAI

LOGGER = logging.getLogger(__name__)

DEFAULT_MODEL = "gpt-4o-mini"
FALLBACK_MODEL = "gpt-3.5-turbo"

__all__ = ["AIAnalyzer"]


class AIAnalyzer:
    def __init__(self) -> None:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable is required.")
        self.client = OpenAI(api_key=api_key)

    def analyze_impact(self, diff_text: str, file_contexts: List[Mapping[str, str]]) -> Dict[str, Any]:
        if not diff_text.strip() and not file_contexts:
            LOGGER.warning("No diff or file contexts provided to AI analyzer.")
            return {"score": 0, "findings": [], "summary": "No changes to analyze."}

        trimmed_diff = diff_text.strip()
        if trimmed_diff and len(trimmed_diff) > 8000:
            trimmed_diff = trimmed_diff[:8000]
            LOGGER.info("Diff truncated to 8k characters for token efficiency.")

        serialized_contexts = json.dumps(file_contexts, ensure_ascii=False)

        prompt = (
            "Analyze the provided diff and FileContext list to predict "
            "1) Potential system breakage, 2) Security flaws, 3) Architectural regressions, "
            "4) Broken imports or logic inconsistencies. "
            "Return a JSON object with risk_score (0-100) and findings. "
            "Each finding MUST include: file, line_number, issue, summary, suggested_fix (code or instruction), "
            "confidence_score (0.0-1.0), and optional snippet. "
            f"Diff:\n{trimmed_diff or 'N/A'}\n"
            f"FileContexts:\n{serialized_contexts}"
        )

        try:
            response = self.client.chat.completions.create(
                model=DEFAULT_MODEL,
                temperature=0.1,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are analyzing full files that have been modified. "
                            "For every issue found, provide file, line_number, issue, summary, snippet if relevant, "
                            "a suggested_fix (code or instruction), and a confidence_score between 0.0 and 1.0. "
                            "Focus on logic errors, broken imports, and architectural inconsistencies."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
            )
        except Exception as exc:
            LOGGER.error("Primary AI model failed: %s", exc)
            if DEFAULT_MODEL == FALLBACK_MODEL:
                return {"score": None, "findings": [], "summary": "AI analysis unavailable."}
            return self._attempt_fallback(prompt)

        return _parse_ai_response(response.choices[0].message.content)

    def _attempt_fallback(self, prompt: str) -> Dict[str, Any]:
        try:
            response = self.client.chat.completions.create(
                model=FALLBACK_MODEL,
                temperature=0.1,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are analyzing full files that have been modified. "
                            "For every issue found, provide file, line_number, issue, summary, snippet if relevant, "
                            "a suggested_fix (code or instruction), and a confidence_score between 0.0 and 1.0. "
                            "Focus on logic errors, broken imports, and architectural inconsistencies."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
            )
            return _parse_ai_response(response.choices[0].message.content)
        except Exception as exc:
            LOGGER.error("Fallback AI model failed: %s", exc)
            return {"score": None, "findings": [], "summary": "AI analysis unavailable."}


def _parse_ai_response(content: str) -> Dict[str, Any]:
    try:
        # CLEANUP: Strip Markdown formatting if the AI adds it
        cleaned_content = content.strip()
        if cleaned_content.startswith("```json"):
            cleaned_content = cleaned_content[7:]
        if cleaned_content.startswith("```"):
            cleaned_content = cleaned_content[3:]
        if cleaned_content.endswith("```"):
            cleaned_content = cleaned_content[:-3]
        
        payload = json.loads(cleaned_content.strip())
        
        # ... (Rest of the logic stays the same) ...
        raw_findings = payload.get("findings", [])
        normalized_findings: List[Dict[str, Any]] = []
        for item in raw_findings:
            normalized_findings.append(
                {
                    "file": item.get("file", "unknown"),
                    "line_number": item.get("line_number", 0),
                    "issue": item.get("issue") or item.get("summary", "AI flagged issue."),
                    "summary": item.get("summary", "No summary provided."),
                    "suggested_fix": item.get("suggested_fix", "No suggested fix provided."),
                    "confidence_score": float(item.get("confidence_score", 0.0)),
                    "snippet": item.get("snippet", ""),
                    "severity": item.get("severity", "medium"),
                }
            )
        return {
            "score": int(payload.get("risk_score", 0)),
            "findings": normalized_findings,
            "summary": payload.get("summary") or payload.get("opinion", "AI summary unavailable."),
        }
    except (ValueError, TypeError) as exc:
        LOGGER.error("Invalid AI response payload. Raw content: %s | Error: %s", content, exc)
        return {"score": None, "findings": [], "summary": "AI analysis parsing failed."}

