"""
Prompt module for HTTPS / cleartext-traffic scanner reports.

Reports produced by scan_https.py — one *_https_report.jsonl per app
in reports/https_check/, with each line shaped like:

  {
    "issue": "hardcoded HTTP URL in bytecode",
    "layer": "dex_strings",
    "context": {"url": "..."},
    "details": {"reason": "..."}
  }
"""

from pathlib import Path

REPORT_DIR = Path("reports/https_check")
GLOB = "*_https_report.jsonl"


PROMPT = """You are labeling a static-analysis alert. The scanner detects this vulnerability class:

  "An Android app transmits data over insecure HTTP instead of HTTPS, or is configured to allow cleartext traffic."

Decide whether the alert below is a TRUE POSITIVE (the scanner correctly identified a real insecure HTTP usage — e.g. a live API endpoint, a cleartext-enabled manifest flag, or a plain socket bypassing TLS) or a FALSE POSITIVE (the scanner is wrong — e.g. the URL is a documentation link, a schema namespace, a dead string constant never used in a network call, or an internal localhost address that the noise filter missed).

Do NOT consider whether the HTTP usage is intentional or whether the app "works fine." Only judge whether the scanner's claim matches reality given the evidence below.

Layer: {layer}
Issue: {issue}
Reason: {reason}
Context: {context}

Reply with EXACTLY one word: "true" or "false". No other text."""


def build_prompt(issue: dict) -> str:
    return PROMPT.format(
        layer=issue["layer"],
        issue=issue["issue"],
        reason=issue["details"]["reason"],
        context=issue["context"],
    )