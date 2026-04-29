import json
import logging
import re
from pathlib import Path

from androguard.core.apk import APK
from lxml import etree


APK_DIRS = [Path("100_apps_a"), Path("99_apks-9_per_category")]
REPORT_DIR = Path("reports/deprecated_perms")
LOG_PATH = Path("scan_apks.log")

# list of perms and when they were depricated. 
deprecated_perms = {
    "android.permission.BIND_CARRIER_MESSAGING_SERVICE": 23,
    "android.permission.BIND_CHOOSER_TARGET_SERVICE": 30,
    "android.permission.GET_TASKS": 21,
    "android.permission.PERSISTENT_ACTIVITY": 15,
    "android.permission.PROCESS_OUTGOING_CALLS": 29,
    "android.permission.READ_INPUT_STATE": 16,
    "android.permission.RESTART_PACKAGES": 15,
    "android.permission.SET_PREFERRED_APPLICATIONS": 15,
    "android.permission.SMS_FINANCIAL_TRANSACTIONS": 31,
    "android.permission.USE_FINGERPRINT": 28,
    "android.permission.READ_EXTERNAL_STORAGE": 33,
    "android.permission.WRITE_EXTERNAL_STORAGE": 33,
    "android.permission.READ_MEDIA_STORAGE": 33,
    "android.permission.SCORE_NETWORKS": 33,
    "android.permission.CONNECTIVITY_INTERNAL": 30,
    "android.permission.BROADCAST_NETWORK_PRIVILEGED": 31,
    "android.permission.MODIFY_NETWORK_ACCOUNTING": 30,
    "android.permission.ACCESS_FM_RADIO": 29,
    "android.permission.WRITE_MEDIA_STORAGE": 33,
    "android.permission.MANAGE_ACTIVITY_STACKS": 31,
    "android.permission.HIDE_NON_SYSTEM_OVERLAY_WINDOWS": 31,
    "android.permission.BIND_CONNECTION_SERVICE": 30,
    "android.permission.RUN_IN_BACKGROUND": 26,
    "android.permission.USE_DATA_IN_BACKGROUND": 26,
    "android.permission.QUERY_TIME_ZONE_RULES": 31,
    "android.permission.UPDATE_TIME_ZONE_RULES": 31,
    "android.permission.GRANT_PROFILE_OWNER_DEVICE_IDS_ACCESS": 31,
}

def get_target_sdk(apk: APK) -> int | None:
    """Return targetSdkVersion as int, or None if missing."""
    target = apk.get_target_sdk_version()
    if target is None:
        # Fall back to effective target if available
        target = apk.get_effective_target_sdk_version()
    try:
        return int(target) if target is not None else None
    except (TypeError, ValueError):
        return None


def get_manifest_xml(apk: APK) -> str:
    """Return the AndroidManifest.xml as a pretty-printed string."""
    manifest_elem = apk.get_android_manifest_xml()
    return etree.tostring(manifest_elem, pretty_print=True, encoding="unicode")


def find_permission_line(manifest_text: str, perm_name: str) -> tuple[str, int] | None:
    """
    Find the <uses-permission .../> line that declares perm_name.
    Returns (line_text, line_number) or None.
    """
    # androguard strips the android: namespace prefix in some versions,
    # so match both forms.
    pattern = re.compile(
        r'<uses-permission[^>]*name\s*=\s*["\']' + re.escape(perm_name) + r'["\'][^>]*/?>'
    )
    for i, line in enumerate(manifest_text.splitlines(), start=1):
        if pattern.search(line):
            return line.strip(), i
    return None


def scan_apk(apk_path: Path) -> list[dict]:
    apk = APK(str(apk_path))
    target_sdk = get_target_sdk(apk)
    permissions = apk.get_permissions()
    manifest_text = get_manifest_xml(apk)

    issues = []
    for perm in permissions:
        if perm not in deprecated_perms:
            continue

        deprecated_at = deprecated_perms[perm]

        # Flag only if the app targets an SDK at or above the deprecation level.
        # If we can't determine target SDK, flag it conservatively.
        if target_sdk is not None and target_sdk < deprecated_at:
            continue

        match = find_permission_line(manifest_text, perm)
        if match:
            line_text, line_num = match
        else:
            line_text, line_num = "<not found in manifest>", -1

        issues.append({
            "issue": f"outdated api ({perm})",
            "context": {
                "line": line_text,
                "line_number": line_num,
                "file": "AndroidManifest.xml",
            },
            "details": {
                "permission": perm,
                "deprecated_at_api": deprecated_at,
                "app_target_sdk": target_sdk,
            },
        })

    return issues


def write_report(app_name: str, issues: list[dict]) -> Path | None:
    """Write issues to REPORT_DIR/<app_name>_report.jsonl. Skip if no issues."""
    if not issues:
        return None
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_DIR / f"{app_name}_report.jsonl"
    with open(report_path, "w", encoding="utf-8") as f:
        for issue in issues:
            f.write(json.dumps(issue) + "\n")
    return report_path


def main():
    apk_files = []
    for d in APK_DIRS:
        if not d.exists():
            continue
        apk_files.extend(sorted(d.glob("*.apk")))

    if not apk_files:
        return

    total_issues = 0
    flagged_apps = 0

    for apk_path in apk_files:
        app_name = apk_path.stem
        try:
            issues = scan_apk(apk_path)
            report_path = write_report(app_name, issues)
            if report_path:
                flagged_apps += 1
                total_issues += len(issues)
        except Exception as e:
            continue


if __name__ == "__main__":
    main()