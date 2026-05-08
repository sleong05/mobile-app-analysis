"""
Prompt module for overprivileged-permissions scanner reports.

Reports produced by scan_overprivileged.py — one *_permissions_report.jsonl
per app in reports/permissions/, with each line shaped like:

  {
    "issue": "declared but unused permission",
    "context": {"permission": "android.permission.CAMERA"},
    "details": {
      "reason": "...",
      "indicators_checked": ["open", "openCamera", ...]
    }
  }
"""

from pathlib import Path

REPORT_DIR = Path("reports/permissions")
GLOB = "*_permissions_report.jsonl"


PROMPT = """You are labeling a static-analysis alert. The scanner detects this vulnerability class:

  "An Android app declares a dangerous permission in its manifest but shows no evidence of using the corresponding API in its DEX bytecode — suggesting the permission is unnecessary and violates least-privilege."

Decide whether the alert below is a TRUE POSITIVE (the permission genuinely appears unused — no matching API call or string reference was found, and the permission should be removed) or a FALSE POSITIVE (the scanner is wrong — e.g. the API is accessed via reflection with a string the scanner did not recognise, the permission is used by a third-party SDK whose strings differ from the indicators checked, or the indicators list is too narrow to cover this permission's actual API surface).

Do NOT consider whether the over-declaration is intentional or harmless. Only judge whether the scanner's claim — that no usage evidence exists — is likely correct given the indicators it checked.

Permission: {permission}
Issue: {issue}
Reason: {reason}
Indicators checked: {indicators}

Reply with EXACTLY one word: "true" or "false". No other text."""


def build_prompt(issue: dict) -> str:
    return PROMPT.format(
        permission=issue["context"]["permission"],
        issue=issue["issue"],
        reason=issue["details"]["reason"],
        indicators=issue["details"].get("indicators_checked", []),
    )