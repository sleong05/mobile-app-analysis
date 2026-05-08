"""
Prompt module for exported-components scanner reports.

Reports produced by scan_exported_components.py — one
*_exported_components_report.jsonl per app in reports/exported_components/,
with each line shaped like:

  {
    "issue": "exported component with no permission protection",
    "layer": "manifest",
    "context": {"component_type": "activity", "component_name": "...", ...},
    "details": {"reason": "..."}
  }

Five issue types are possible:
  - "exported component with no permission protection"
  - "implicitly exported component — protection unclear"
  - "exported component handles sensitive intent actions"
  - "ContentProvider path-permissions without top-level permission"
  - "ContentProvider grants URI permissions without read/write permission"
  - "deep-link activity with custom URI scheme and no permission"
  - "Intent extra data read without apparent input validation"
"""

from pathlib import Path

REPORT_DIR = Path("reports/exported_components")
GLOB = "*_exported_components_report.jsonl"


PROMPT = """You are labeling a static-analysis alert. The scanner detects this vulnerability class:

  "An Android app exposes one or more components (Activity, Service, BroadcastReceiver, or ContentProvider) to other apps without adequate permission protection, allowing any third-party app to invoke, read from, or write to them."

Decide whether the alert below is a TRUE POSITIVE (the scanner correctly identified a component that is genuinely reachable by other apps with no meaningful protection) or a FALSE POSITIVE (the scanner is wrong — e.g. the component is an internal launcher activity that intentionally has no permission, it is a standard system-integration receiver like BOOT_COMPLETED that is expected to be exported, the permission check happens dynamically at runtime rather than being declared in the manifest, or the "implicit export" is on API >= 31 where it would be blocked at install time).

Do NOT consider whether the exposure is intentional or whether the app "works fine." Only judge whether the scanner's claim — that the component is reachable by other apps without meaningful protection — is likely correct given the evidence below.

Issue type: {issue}
Layer: {layer}
Component type: {component_type}
Component name: {component_name}
Reason: {reason}
Context: {context}

Reply with EXACTLY one word: "true" or "false". No other text."""


def build_prompt(issue: dict) -> str:
    context = issue["context"]

    # component_type is present on most issues but not on the dex_invocations one
    component_type = context.get("component_type", "unknown")
    component_name = context.get("component_name", "unknown")

    return PROMPT.format(
        issue=issue["issue"],
        layer=issue["layer"],
        component_type=component_type,
        component_name=component_name,
        reason=issue["details"]["reason"],
        context=context,
    )