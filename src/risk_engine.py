import logging
import math
import re
from collections import defaultdict
from typing import Any, Dict, List, Mapping

LOGGER = logging.getLogger(__name__)

SECRET_PATTERNS: Dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "generic_api_key": re.compile(r"(?i)(api[_-]?key|token)['\"]?\s*[:=]\s*['\"][A-Za-z0-9-]{20,}"),
    "private_key": re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,48}"),
}

STRING_LITERAL_PATTERN = re.compile(r"(['\"])(?P<value>[A-Za-z0-9+/=_:-]{13,})\1")
EXCLUDED_SEGMENTS = ("/test/", "/tests/", "/docs/", "__test__")
CHURN_THRESHOLD = 200

__all__ = ["evaluate_static_risks", "calculate_entropy"]


def evaluate_static_risks(diff_text: str) -> Dict[str, Any]:
    if not diff_text:
        LOGGER.warning("Empty diff received by risk engine; returning zero risk.")
        return {"score": 0, "findings": []}

    findings: List[Dict[str, Any]] = []
    churn_track: Dict[str, int] = {}
    current_file = None
    current_line = 0
    file_nodes: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:]
            LOGGER.debug("Processing file %s", current_file)
            continue

        if raw_line.startswith("@@"):
            current_line = _parse_new_line_number(raw_line)
            continue

        if not current_file:
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            current_line += 1
            content = raw_line[1:]
            file_nodes[current_file].append({"type": "add", "line": current_line, "content": content})

            if _is_ignored_file(current_file):
                continue

            if any(s in current_file.lower() for s in ["auth", "login", "crypto", "payment", "security"]):
                 findings.append({
                    "file": current_file,
                    "line": 0, 
                    "issue": "Modification to critical system component.",
                    "severity": "medium", 
                    "tag": "sensitive_file"
                 })

            churn_track[current_file] = churn_track.get(current_file, 0) + 1
            node_index = len(file_nodes[current_file]) - 1
            findings.extend(
                _detect_secrets(current_file, current_line, content, file_nodes[current_file], node_index)
            )
            findings.extend(
                _detect_entropy_risk(current_file, current_line, content, file_nodes[current_file], node_index)
            )
            continue

        if raw_line.startswith(" "):
            current_line += 1
            file_nodes[current_file].append({"type": "context", "line": current_line, "content": raw_line[1:]})
            continue

        if not raw_line.startswith("-"):
            current_line += 1

    churn_findings = _detect_churn(churn_track)
    findings.extend(churn_findings)

    secret_hits = len([f for f in findings if f.get("tag") in {"secret", "entropy"}])
    churn_hits = len(churn_findings)

    score = min(100, secret_hits * 20 + churn_hits * 10)
    LOGGER.info("Static risk score computed as %d (secrets=%d churn=%d)", score, secret_hits, churn_hits)
    return {"score": score, "findings": findings}


def calculate_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    frequencies: Dict[str, int] = {}
    for char in value:
        frequencies[char] = frequencies.get(char, 0) + 1
    entropy = 0.0
    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def _parse_new_line_number(hunk_header: str) -> int:
    try:
        addition_segment = hunk_header.split("+")[1]
        addition_range = addition_segment.split(" ")[0]
        return int(addition_range.split(",")[0])
    except (IndexError, ValueError):
        LOGGER.error("Unable to parse hunk header: %s", hunk_header)
        return 0


def _detect_secrets(
    file_path: str,
    line_number: int,
    content: str,
    nodes: List[Mapping[str, Any]],
    node_index: int,
) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []
    for key, pattern in SECRET_PATTERNS.items():
        if pattern.search(content):
            matches.append(
                {
                    "file": file_path,
                    "line": line_number,
                    "issue": f"Potential {key.replace('_', ' ')} detected.",
                    "severity": "high",
                    "tag": "secret",
                    "snippet": _build_snippet(nodes, node_index),
                }
            )
    return matches


def _detect_entropy_risk(
    file_path: str,
    line_number: int,
    content: str,
    nodes: List[Mapping[str, Any]],
    node_index: int,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for match in STRING_LITERAL_PATTERN.finditer(content):
        candidate = match.group("value")
        entropy = calculate_entropy(candidate)
        if entropy > 4.5:
            findings.append(
                {
                    "file": file_path,
                    "line": line_number,
                    "issue": "Potential high-entropy secret detected.",
                    "severity": "high",
                    "tag": "entropy",
                    "snippet": _build_snippet(nodes, node_index),
                    "metadata": {"entropy": round(entropy, 2)},
                }
            )
    return findings


def _detect_churn(churn_track: Dict[str, int]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for file_path, additions in churn_track.items():
        if additions >= CHURN_THRESHOLD:
            findings.append(
                {
                    "file": file_path,
                    "line": 0,
                    "issue": f"High churn detected ({additions} added lines).",
                    "severity": "medium",
                    "tag": "churn",
                }
            )
    return findings


def _build_snippet(nodes: List[Mapping[str, Any]], index: int, radius: int = 2) -> str:
    if not nodes:
        return ""
    start = max(0, index - radius)
    end = min(len(nodes), index + radius + 1)
    snippet_lines = [str(nodes[i].get("content", "")).rstrip() for i in range(start, end)]
    return "\n".join(line for line in snippet_lines if line)


def _is_ignored_file(file_path: str) -> bool:
    lowered = file_path.lower()
    return any(segment in lowered for segment in EXCLUDED_SEGMENTS)

