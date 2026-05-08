"""
Prompt module for SSL / certificate-verification scanner reports.

Reports are produced by scan_ssl.py — one *_ssl_report.jsonl per app
in reports_ssl/, with each line shaped like:

  {
    "issue": "insecure checkServerTrusted (empty)",
    "context": {"class": "...", "method": "...", "body": "..."},
    "details": {"reason": "..."}
  }
"""

from pathlib import Path

REPORT_DIR = Path("reports/cert_verification")
GLOB = "*_ssl_report.jsonl"


PROMPT = """You are labeling a static-analysis alert. The scanner detects this vulnerability class:

  "A class implementing javax.net.ssl.X509TrustManager has a checkServerTrusted method that does not properly validate certificates (empty body, no throw, or throws a non-certificate exception)."

Decide whether the alert below is a TRUE POSITIVE (the scanner correctly identified a checkServerTrusted method that fails to validate the certificate chain) or a FALSE POSITIVE (the scanner is wrong — e.g., the method is abstract / has no body because it's an interface stub the framework supplies elsewhere, the bytecode actually does validate but the scanner missed it, or the class isn't really a TrustManager).

Class: {cls}
Method: {method}
Scanner verdict: {issue}
Reason: {reason}

Method body (smali/dex disassembly):
{body}

Reply with EXACTLY one word: "true" or "false". No other text."""


def build_prompt(issue: dict) -> str:
    return PROMPT.format(
        cls=issue["context"]["class"],
        method=issue["context"]["method"],
        issue=issue["issue"],
        reason=issue["details"]["reason"],
        body=issue["context"].get("body") or "<no body>",
    )