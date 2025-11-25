import base64
import logging
from typing import Any, Dict, List, Mapping

import requests
from github import Github
import gitlab

LOGGER = logging.getLogger(__name__)

MAX_FILE_LINES = 2000

__all__ = ["detect_provider", "fetch_context", "post_comment"]


def detect_provider(env: Mapping[str, str]) -> Dict[str, Any]:
    """Determine SCM provider context using environment metadata."""
    github_repo = env.get("GITHUB_REPOSITORY")
    pr_number = env.get("PR_NUMBER") or env.get("GITHUB_PR_NUMBER")
    gitlab_project = env.get("GITLAB_PROJECT_ID")
    mr_iid = env.get("MR_IID") or env.get("GITLAB_MR_IID")

    if github_repo and pr_number:
        token = env.get("GITHUB_TOKEN")
        if not token:
            raise ValueError("GITHUB_TOKEN is required for GitHub operations.")
        LOGGER.info("Detected GitHub provider for repository %s", github_repo)
        return {
            "provider": "github",
            "repository": github_repo,
            "pull_number": int(pr_number),
            "token": token,
        }

    if gitlab_project and mr_iid:
        token = env.get("GITLAB_TOKEN")
        if not token:
            raise ValueError("GITLAB_TOKEN is required for GitLab operations.")
        LOGGER.info("Detected GitLab provider for project %s", gitlab_project)
        return {
            "provider": "gitlab",
            "project_id": gitlab_project,
            "mr_iid": int(mr_iid),
            "token": token,
            "url": env.get("GITLAB_URL", "https://gitlab.com"),
        }

    raise ValueError("Unable to determine SCM provider; check CI environment variables.")


def fetch_context(context: Mapping[str, Any]) -> Dict[str, Any]:
    """Fetch diff plus full context for changed files."""
    provider = context["provider"]

    if provider == "github":
        return _fetch_github_context(context)

    if provider == "gitlab":
        return _fetch_gitlab_context(context)

    raise ValueError(f"Unsupported provider {provider}")


def post_comment(context: Mapping[str, Any], body: str) -> Dict[str, Any]:
    """Post a Markdown comment on the PR/MR with the RepoGuard report."""
    provider = context["provider"]

    if provider == "github":
        client = Github(context["token"])
        repo = client.get_repo(context["repository"])
        pr = repo.get_pull(context["pull_number"])
        pr.create_issue_comment(body)
        return {"provider": provider, "status": "posted"}

    if provider == "gitlab":
        client = gitlab.Gitlab(context["url"], private_token=context["token"])
        project = client.projects.get(context["project_id"])
        mr = project.mergerequests.get(context["mr_iid"])
        mr.notes.create({"body": body})
        return {"provider": provider, "status": "posted"}

    raise ValueError(f"Unsupported provider {provider}")


def _fetch_github_context(context: Mapping[str, Any]) -> Dict[str, Any]:
    client = Github(context["token"])
    repo = client.get_repo(context["repository"])
    pr = repo.get_pull(context["pull_number"])
    diff_text = _download_github_diff(pr.url, context["token"])
    file_contexts: List[Dict[str, str]] = []
    for file in pr.get_files():
        if file.status == "removed":
            LOGGER.debug("Skipping removed file %s", file.filename)
            continue
        try:
            blob = repo.get_contents(file.filename, ref=pr.head.sha)
            decoded = blob.decoded_content.decode("utf-8", errors="replace")
            file_contexts.append(
                {
                    "path": file.filename,
                    "content": _truncate_content(decoded),
                }
            )
        except Exception as exc:
            LOGGER.error("Unable to fetch GitHub file content for %s: %s", file.filename, exc)
    LOGGER.info("Collected context for %d GitHub files", len(file_contexts))
    return {"diff_text": diff_text, "files": file_contexts}


def _fetch_gitlab_context(context: Mapping[str, Any]) -> Dict[str, Any]:
    client = gitlab.Gitlab(context["url"], private_token=context["token"])
    project = client.projects.get(context["project_id"])
    mr = project.mergerequests.get(context["mr_iid"])
    changes = mr.changes()
    diffs = []
    file_contexts: List[Dict[str, str]] = []
    ref = getattr(mr, "sha", None) or mr.attributes.get("sha") or mr.attributes.get("diff_refs", {}).get("head_sha")
    ref = ref or mr.target_branch
    for change in changes.get("changes", []):
        diff = change.get("diff", "")
        if diff:
            diffs.append(diff)
        new_path = change.get("new_path") or change.get("new_file") or change.get("new_file_path")
        if not new_path or change.get("deleted_file"):
            continue
        try:
            file_obj = project.files.get(file_path=new_path, ref=ref)
            decoded = base64.b64decode(file_obj.content).decode("utf-8", errors="replace")
            file_contexts.append(
                {
                    "path": new_path,
                    "content": _truncate_content(decoded),
                }
            )
        except Exception as exc:
            LOGGER.error("Unable to fetch GitLab file content for %s: %s", new_path, exc)
    diff_text = "\n".join(diffs)
    LOGGER.info("Collected context for %d GitLab files", len(file_contexts))
    return {"diff_text": diff_text, "files": file_contexts}


def _download_github_diff(pr_url: str, token: str) -> str:
    headers = {
        "Accept": "application/vnd.github.v3.diff",
        "Authorization": f"token {token}",
        "User-Agent": "RepoGuard-Agent",
    }
    response = requests.get(pr_url, headers=headers, timeout=30)
    response.raise_for_status()
    LOGGER.debug("Fetched %d bytes of GitHub diff data", len(response.text))
    return response.text


def _truncate_content(content: str) -> str:
    lines = content.splitlines()
    if len(lines) <= MAX_FILE_LINES:
        return content
    LOGGER.warning("Truncating file context to %d lines", MAX_FILE_LINES)
    truncated = "\n".join(lines[:MAX_FILE_LINES])
    return f"{truncated}\n...TRUNCATED..."

