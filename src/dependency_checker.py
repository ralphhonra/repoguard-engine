import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
from Levenshtein import distance as levenshtein_distance

LOGGER = logging.getLogger(__name__)

MONITORED_FILES = {
    "requirements.txt",
    "package.json",
    "pyproject.toml",
    "poetry.lock",
    "Dockerfile",
    "pom.xml"
}

KNOWN_SAFE_PACKAGES = [
    "requests",
    "flask",
    "django",
    "numpy",
    "pandas",
    "express",
    "react",
    "lodash",
]

NEW_PACKAGE_THRESHOLD_DAYS = 30
PYPI_CACHE: Dict[str, Optional[int]] = {}
NPM_CACHE: Dict[str, Optional[int]] = {}

__all__ = ["evaluate_supply_chain"]


def evaluate_supply_chain(diff_text: str) -> Dict[str, Any]:
    if not diff_text:
        LOGGER.warning("Empty diff received by dependency checker; returning zero risk.")
        return {"score": 0, "findings": []}

    findings: List[Dict[str, Any]] = []
    current_file = None

    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue

        if not current_file or not _is_monitored_file(current_file):
            continue

        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:].strip()
            if not content or content.startswith("#"):
                continue
            findings.extend(_inspect_dependency_line(current_file, content))

    score = min(100, len(findings) * 25)
    LOGGER.info("Supply chain risk score computed as %d with %d findings", score, len(findings))
    return {"score": score, "findings": findings}


def _is_monitored_file(file_path: str) -> bool:
    lowered = file_path.lower()
    return any(lowered.endswith(candidate.lower()) for candidate in MONITORED_FILES)


def _inspect_dependency_line(file_path: str, content: str) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []

    if "http://" in content:
        alerts.append(
            _build_alert(
                file_path,
                "Dependency pulled from non-TLS endpoint.",
                "high",
                "supply_chain",
                content,
            )
        )

    package_name = _extract_package_name(file_path, content)
    if not package_name:
        return alerts

    if "git+" in content or package_name.startswith("git+"):
        alerts.append(
            _build_alert(
                file_path,
                f"Unpinned VCS dependency detected ({content}).",
                "medium",
                "supply_chain",
                content,
            )
        )

    version_spec = _extract_version_spec(file_path, content)

    if _is_unpinned_version(version_spec):
        alerts.append(
            _build_alert(
                file_path,
                "Unpinned dependency version (Risk of supply chain injection).",
                "medium",
                "version",
                content,
            )
        )

    if file_path.endswith("requirements.txt") and "==" not in content:
        alerts.append(
            _build_alert(
                file_path,
                f"Unpinned Python dependency ({package_name}).",
                "medium",
                "supply_chain",
                content,
            )
        )

    if _looks_like_typosquat(package_name):
        alerts.append(
            _build_alert(
                file_path,
                f"Potential typosquatting attempt ({package_name}).",
                "high",
                "typosquat",
                content,
            )
        )

    age_days = _fetch_package_age_days(package_name, file_path)
    if age_days is not None and age_days < NEW_PACKAGE_THRESHOLD_DAYS:
        alerts.append(
            _build_alert(
                file_path,
                f"Newly published dependency ({package_name}) detected ({age_days} days old).",
                "medium",
                "new_package",
                content,
            )
        )

    return alerts


def _build_alert(
    file_path: str,
    issue: str,
    severity: str,
    tag: str,
    snippet: str,
) -> Dict[str, Any]:
    return {
        "file": file_path,
        "line": 0,
        "issue": issue,
        "severity": severity,
        "tag": tag,
        "snippet": snippet,
    }


def _extract_package_name(file_path: str, content: str) -> str:
    lowered = file_path.lower()
    if lowered.endswith("requirements.txt"):
        return content.split("==")[0].strip()

    if lowered.endswith("package.json"):
        if ":" in content:
            return content.split(":")[0].strip().strip('"').strip("'").strip(",")

    # NEW: Java Maven Support
    if lowered.endswith("pom.xml"):
        # Simple check for <artifactId>...</artifactId>
        if "artifactId" in content:
            # Extract text between tags >...<
            try:
                return content.split(">")[1].split("<")[0]
            except IndexError:
                return content.strip()

    if lowered.endswith("dockerfile"):
        tokens = content.split()
        if tokens and tokens[0].lower() == "run":
            return tokens[-1]

    return content.split()[0]


def _extract_version_spec(file_path: str, content: str) -> str:
    lowered = file_path.lower()
    if lowered.endswith("requirements.txt"):
        if "==" in content:
            return content.split("==", 1)[1].strip()
        return ""

    if lowered.endswith("package.json") and ":" in content:
        version_fragment = content.split(":", 1)[1]
        version_fragment = version_fragment.strip().strip(",").strip()
        return version_fragment.strip('"').strip("'")

    return ""


def _is_unpinned_version(version_spec: str) -> bool:
    if not version_spec:
        return False
    normalized = version_spec.lower()
    if normalized in {"*", "latest"}:
        return True
    return "*" in normalized or normalized.startswith(("^", "~"))


def _looks_like_typosquat(package_name: str) -> bool:
    normalized = package_name.lower()
    for safe in KNOWN_SAFE_PACKAGES:
        if normalized == safe:
            return False
        if levenshtein_distance(normalized, safe) == 1:
            return True
    return False


def _fetch_package_age_days(package_name: str, file_path: str) -> Optional[int]:
    lowered = file_path.lower()
    if lowered.endswith("requirements.txt"):
        if package_name in PYPI_CACHE:
            return PYPI_CACHE[package_name]
        age = _query_pypi_age(package_name)
        PYPI_CACHE[package_name] = age
        return age

    if lowered.endswith("package.json"):
        if package_name in NPM_CACHE:
            return NPM_CACHE[package_name]
        age = _query_npm_age(package_name)
        NPM_CACHE[package_name] = age
        return age

    return None


def _query_pypi_age(package_name: str) -> Optional[int]:
    try:
        response = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=10)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        LOGGER.warning("Unable to query PyPI for %s: %s", package_name, exc)
        return None

    upload_times: List[datetime] = []
    for release_files in payload.get("releases", {}).values():
        for file_meta in release_files:
            stamp = file_meta.get("upload_time_iso_8601")
            parsed = _parse_iso8601(stamp)
            if parsed:
                upload_times.append(parsed)

    if not upload_times:
        return None

    latest_upload = max(upload_times)
    return (datetime.now(timezone.utc) - latest_upload).days


def _query_npm_age(package_name: str) -> Optional[int]:
    try:
        response = requests.get(f"https://registry.npmjs.org/{package_name}", timeout=10)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        LOGGER.warning("Unable to query npm for %s: %s", package_name, exc)
        return None

    time_block = payload.get("time", {})
    modified = time_block.get("modified") or time_block.get("created")
    parsed = _parse_iso8601(modified)
    if not parsed:
        return None

    return (datetime.now(timezone.utc) - parsed).days


def _parse_iso8601(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except ValueError:
        LOGGER.debug("Unable to parse timestamp %s", value)
        return None

