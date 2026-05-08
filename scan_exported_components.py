import json
from pathlib import Path

from androguard.core.apk import APK
from androguard.core.dex import DEX


APK_DIRS = [Path("100_apps_a"), Path("99_apks-9_per_category")]
REPORT_DIR = Path("reports/exported_components")

# Component types that can be exported
COMPONENT_TYPES = ["activity", "service", "receiver", "provider"]

# Permissions that are considered meaningful protection
# (system-defined dangerous or signature permissions)
STRONG_PERMISSION_PREFIXES = [
    "android.permission.",
    "com.google.android.permission.",
]

# Permissions that are too weak to count as real protection
WEAK_PERMISSIONS = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.FOREGROUND_SERVICE",
}

# Intent actions that are implicitly exported (high-value targets)
SENSITIVE_INTENT_ACTIONS = [
    "android.intent.action.SEND",
    "android.intent.action.SENDTO",
    "android.intent.action.VIEW",
    "android.intent.action.EDIT",
    "android.intent.action.PICK",
    "android.intent.action.CALL",
    "android.intent.action.PROCESS_TEXT",
    "android.nfc.action.NDEF_DISCOVERED",
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.MY_PACKAGE_REPLACED",
]

# DEX method indicators for sensitive operations inside components
SENSITIVE_COMPONENT_APIS = [
    "getIntent",
    "getExtras",
    "getStringExtra",
    "getParcelableExtra",
    "onStartCommand",
    "onHandleIntent",
    "onReceive",
    "query",
    "insert",
    "update",
    "delete",
    "openFile",
    "call",
]

# Android namespace shorthand
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


# Helpers

def _attr(el, name: str) -> str | None:
    """Return an AndroidManifest XML attribute value, or None."""
    return el.get(f"{ANDROID_NS}{name}")


def _is_strong_permission(perm: str | None) -> bool:
    """True if the permission string looks like a meaningful protection level."""
    if not perm:
        return False
    if perm in WEAK_PERMISSIONS:
        return False
    return any(perm.startswith(pfx) for pfx in STRONG_PERMISSION_PREFIXES) or "." in perm


def _component_is_exported(el, component_type: str) -> bool | None:
    """
    Determine export status.
    Returns True (exported), False (not exported), or None (ambiguous/implicit).
    """
    exported_val = _attr(el, "exported")
    if exported_val is not None:
        return exported_val.lower() == "true"

    # Implicit export: component has an <intent-filter> and no explicit exported=false
    has_intent_filter = el.find("intent-filter") is not None
    if has_intent_filter:
        # On API >= 31, components with intent filters require explicit exported attr.
        # For older apps, presence of intent-filter implies exported=true.
        return None  # ambiguous — flag for review

    # Providers default to exported=true on API < 17
    if component_type == "provider":
        return None  # ambiguous — flag for review

    return False


def _get_intent_actions(el) -> list[str]:
    """Collect all intent action names from an element's intent-filter children."""
    actions = []
    for intent_filter in el.findall("intent-filter"):
        for action in intent_filter.findall("action"):
            name = _attr(action, "name")
            if name:
                actions.append(name)
    return actions


# Per-layer checks

def check_exported_components(apk: APK) -> list[dict]:
    """
    Inspect AndroidManifest.xml for exported components that lack proper
    permission protection or have other misconfigurations.
    """
    issues = []
    manifest_xml = apk.get_android_manifest_xml()
    if manifest_xml is None:
        return issues

    app_el = manifest_xml.find(".//application")
    if app_el is None:
        return issues

    for comp_type in COMPONENT_TYPES:
        for el in app_el.findall(comp_type):
            name = _attr(el, "name") or "<unnamed>"
            exported = _component_is_exported(el, comp_type)
            permission = _attr(el, "permission")
            read_perm = _attr(el, "readPermission")   # provider-specific
            write_perm = _attr(el, "writePermission")  # provider-specific
            intent_actions = _get_intent_actions(el)

            # Not exported and unambiguous — skip
            if exported is False:
                continue

            # Exported with no permission guard
            if exported is True and not _is_strong_permission(permission):
                # Providers also need read/write permissions
                if comp_type == "provider":
                    if not (_is_strong_permission(read_perm) or _is_strong_permission(write_perm)):
                        issues.append({
                            "issue": "exported component with no permission protection",
                            "layer": "manifest",
                            "context": {
                                "component_type": comp_type,
                                "component_name": name,
                                "exported": "true",
                                "permission": permission,
                                "readPermission": read_perm,
                                "writePermission": write_perm,
                            },
                            "details": {
                                "reason": (
                                    f"Exported {comp_type} '{name}' declares no "
                                    "read/write permission — any app can access it."
                                ),
                            },
                        })
                else:
                    issues.append({
                        "issue": "exported component with no permission protection",
                        "layer": "manifest",
                        "context": {
                            "component_type": comp_type,
                            "component_name": name,
                            "exported": "true",
                            "permission": permission,
                        },
                        "details": {
                            "reason": (
                                f"Exported {comp_type} '{name}' requires no permission "
                                "— any third-party app can invoke it directly."
                            ),
                        },
                    })

            # Implicitly exported (intent-filter present, no explicit exported attr)
            if exported is None:
                has_strong = _is_strong_permission(permission)
                issues.append({
                    "issue": "implicitly exported component — protection unclear",
                    "layer": "manifest",
                    "context": {
                        "component_type": comp_type,
                        "component_name": name,
                        "exported": "implicit (intent-filter present, no explicit attribute)",
                        "permission": permission,
                        "intent_actions": intent_actions,
                    },
                    "details": {
                        "reason": (
                            f"{comp_type.capitalize()} '{name}' has an intent-filter but no "
                            "explicit android:exported attribute. On API < 31 this defaults "
                            "to exported=true. "
                            + ("Permission guard present — verify it is enforced at runtime."
                               if has_strong else
                               "No permission guard found — potentially accessible by any app.")
                        ),
                    },
                })

            # Exported component handling a sensitive intent action
            if exported is not False and intent_actions:
                sensitive_hits = [a for a in intent_actions if a in SENSITIVE_INTENT_ACTIONS]
                if sensitive_hits:
                    issues.append({
                        "issue": "exported component handles sensitive intent actions",
                        "layer": "manifest",
                        "context": {
                            "component_type": comp_type,
                            "component_name": name,
                            "sensitive_actions": sensitive_hits,
                        },
                        "details": {
                            "reason": (
                                f"{comp_type.capitalize()} '{name}' is reachable from other "
                                "apps and handles sensitive system intent actions. Verify that "
                                "all incoming Intent data is validated before use."
                            ),
                        },
                    })

    return issues


def check_provider_path_permissions(apk: APK) -> list[dict]:
    """
    ContentProviders may expose only a subset of their data via path-permission
    elements. Flag providers that export path-permissions without a top-level
    permission (creating a path-traversal risk).
    """
    issues = []
    manifest_xml = apk.get_android_manifest_xml()
    if manifest_xml is None:
        return issues

    app_el = manifest_xml.find(".//application")
    if app_el is None:
        return issues

    for el in app_el.findall("provider"):
        name = _attr(el, "name") or "<unnamed>"
        exported = _component_is_exported(el, "provider")
        if exported is False:
            continue

        top_perm = _attr(el, "permission")
        read_perm = _attr(el, "readPermission")
        write_perm = _attr(el, "writePermission")
        has_path_perms = len(el.findall("path-permission")) > 0
        grant_uri = _attr(el, "grantUriPermissions")

        # Provider has fine-grained path permissions but no top-level gate
        if has_path_perms and not any([
            _is_strong_permission(top_perm),
            _is_strong_permission(read_perm),
            _is_strong_permission(write_perm),
        ]):
            issues.append({
                "issue": "ContentProvider path-permissions without top-level permission",
                "layer": "manifest",
                "context": {
                    "component_name": name,
                    "has_path_permission": True,
                    "top_level_permission": top_perm,
                },
                "details": {
                    "reason": (
                        f"Provider '{name}' uses path-permission elements but lacks a "
                        "top-level permission. Paths not matched by path-permission rules "
                        "fall back to the (absent) top-level permission, leaving them unprotected."
                    ),
                },
            })

        # grantUriPermissions=true with no read/write permission is a broad exposure
        if grant_uri and grant_uri.lower() == "true":
            if not (_is_strong_permission(read_perm) or _is_strong_permission(write_perm)):
                issues.append({
                    "issue": "ContentProvider grants URI permissions without read/write permission",
                    "layer": "manifest",
                    "context": {
                        "component_name": name,
                        "grantUriPermissions": "true",
                        "readPermission": read_perm,
                        "writePermission": write_perm,
                    },
                    "details": {
                        "reason": (
                            f"Provider '{name}' has grantUriPermissions=\"true\" but no "
                            "readPermission/writePermission — any app granted a URI can "
                            "read or write without holding a real permission."
                        ),
                    },
                })

    return issues


def check_intent_data_handling(invocations: list[str], dex_strings: list[str]) -> list[dict]:
    """
    Detect whether the app reads Intent extras/data (suggesting components
    process external input) without obvious input-validation indicators.
    Flags for manual review when sensitive API pairs are present.
    """
    reads_intent = any(
        any(api in inv for api in ["getExtras", "getStringExtra", "getParcelableExtra", "getData"])
        for inv in invocations
    )
    uses_uri_parse = any("Uri.parse" in inv or "Uri.parse" in s for inv in invocations for s in [inv])
    validates_input = any(
        kw in s for s in dex_strings
        for kw in ["startsWith", "contains", "matches", "validate", "sanitize", "allowlist", "whitelist"]
    )

    issues = []
    if reads_intent and not validates_input:
        issues.append({
            "issue": "Intent extra data read without apparent input validation",
            "layer": "dex_invocations",
            "context": {
                "reads_intent_extras": reads_intent,
                "uses_uri_parse": uses_uri_parse,
                "has_validation_indicators": validates_input,
            },
            "details": {
                "reason": (
                    "App reads Intent extras/data in bytecode but no common "
                    "validation patterns (startsWith, matches, allowlist, sanitize) "
                    "were found in string constants. Exported components processing "
                    "unvalidated Intent data are vulnerable to Intent injection."
                ),
            },
        })
    return issues


def check_deeplink_exposure(apk: APK) -> list[dict]:
    """
    Activities registered with custom URI schemes (deep links) are de-facto
    exported endpoints. Flag ones that lack a permission guard.
    """
    issues = []
    manifest_xml = apk.get_android_manifest_xml()
    if manifest_xml is None:
        return issues

    app_el = manifest_xml.find(".//application")
    if app_el is None:
        return issues

    for activity in app_el.findall("activity"):
        name = _attr(activity, "name") or "<unnamed>"
        permission = _attr(activity, "permission")

        for intent_filter in activity.findall("intent-filter"):
            for data_el in intent_filter.findall("data"):
                scheme = _attr(data_el, "scheme")
                if scheme and scheme not in ("http", "https", "content", "file"):
                    # Custom deep-link scheme
                    if not _is_strong_permission(permission):
                        issues.append({
                            "issue": "deep-link activity with custom URI scheme and no permission",
                            "layer": "manifest",
                            "context": {
                                "component_name": name,
                                "scheme": scheme,
                                "permission": permission,
                            },
                            "details": {
                                "reason": (
                                    f"Activity '{name}' registers the custom URI scheme '{scheme}://' "
                                    "without a permission guard. Any app can trigger this activity "
                                    "by crafting an Intent with a matching URI."
                                ),
                            },
                        })
                    break  # one report per activity is enough

    return issues


# Utility

def collect_invoked_methods(dex_bytes: bytes) -> list[str]:
    d = DEX(dex_bytes)
    invocations: list[str] = []
    for cls in d.get_classes():
        for method in cls.get_methods():
            try:
                code = method.get_code()
                if code is None:
                    continue
                for ins in code.get_bc().get_instructions():
                    if ins.get_name().startswith("invoke"):
                        invocations.append(ins.get_output() or "")
            except Exception:
                continue
    return invocations


def collect_dex_strings(dex_bytes: bytes) -> list[str]:
    d = DEX(dex_bytes)
    return [str(s) for s in d.get_strings()]


# Orchestration

def scan_apk(apk_path: Path) -> list[dict]:
    apk = APK(str(apk_path))

    all_invocations: list[str] = []
    all_strings: list[str] = []
    for dex_bytes in apk.get_all_dex():
        all_invocations.extend(collect_invoked_methods(dex_bytes))
        all_strings.extend(collect_dex_strings(dex_bytes))

    issues: list[dict] = []
    issues.extend(check_exported_components(apk))
    issues.extend(check_provider_path_permissions(apk))
    issues.extend(check_deeplink_exposure(apk))
    issues.extend(check_intent_data_handling(all_invocations, all_strings))

    return issues


def write_report(app_name: str, issues: list[dict]) -> Path | None:
    if not issues:
        return None
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_DIR / f"{app_name}_exported_components_report.jsonl"
    with open(report_path, "w", encoding="utf-8") as f:
        for issue in issues:
            f.write(json.dumps(issue) + "\n")
    return report_path


def main() -> None:
    apk_files: list[Path] = []
    for d in APK_DIRS:
        if not d.exists():
            continue
        apk_files.extend(sorted(d.glob("*.apk")))

    if not apk_files:
        print("No APK files found.")
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
                by_layer = {}
                for iss in issues:
                    by_layer.setdefault(iss["layer"], 0)
                    by_layer[iss["layer"]] += 1
                layer_summary = ", ".join(f"{k}:{v}" for k, v in by_layer.items())
                print(f"[FLAGGED] {app_name}: {len(issues)} issue(s) [{layer_summary}] -> {report_path}")
            else:
                print(f"[OK]      {app_name}")
        except Exception as e:
            print(f"[ERROR]   {app_name}: {e}")

    print(f"\nDone. {flagged_apps}/{len(apk_files)} apps flagged, {total_issues} total issues.")


if __name__ == "__main__":
    main()