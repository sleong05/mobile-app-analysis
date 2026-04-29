"""
Prompt module for deprecated-permission scanner reports.

Reports are produced by scan_apks.py — one *_report.jsonl per app
in reports/, with each line shaped like:

  {
    "issue": "outdated api (android.permission.GET_TASKS)",
    "context": {"line": "...", "line_number": 12, "file": "AndroidManifest.xml"},
    "details": {"permission": "...", "deprecated_at_api": 21, "app_target_sdk": 33}
  }
"""

from pathlib import Path

REPORT_DIR = Path("reports/deprecated_perms")
GLOB = "*_report.jsonl"


PROMPT = """You are labeling a static-analysis alert. The scanner detects this vulnerability class:

  "App declares an Android permission that has been deprecated at or before the app's targetSdkVersion."

Decide whether the alert below is a TRUE POSITIVE (the scanner correctly identified an instance of this vulnerability class) or a FALSE POSITIVE (the scanner is wrong — e.g., the permission isn't actually deprecated at that API, or the manifest line scopes it to older SDKs via maxSdkVersion so it isn't actually used at the target SDK).

Permission: {perm}
Deprecated at API: {dep_at}
App target SDK: {target}
Manifest line {line_no}: {line}

Reply with EXACTLY one word: "true" or "false". No other text."""


def build_prompt(issue: dict) -> str:
    return PROMPT.format(
        perm=issue["details"]["permission"],
        dep_at=issue["details"]["deprecated_at_api"],
        target=issue["details"].get("app_target_sdk", "unknown"),
        line=issue["context"]["line"],
        line_no=issue["context"]["line_number"],
    )