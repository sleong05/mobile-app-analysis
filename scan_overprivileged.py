import json
from pathlib import Path
 
from androguard.core.apk import APK
from androguard.core.dex import DEX
 
 
APK_DIRS = [Path("100_apps_a"), Path("99_apks-9_per_category")]
REPORT_DIR = Path("reports/permissions")

PERMISSION_API_MAP: dict[str, list[str]] = {
    "android.permission.ACCESS_FINE_LOCATION": [
        "getLastKnownLocation",
        "requestLocationUpdates",
        "getCurrentLocation",
        "getLastLocation",
    ],
    "android.permission.ACCESS_COARSE_LOCATION": [
        "getLastKnownLocation",
        "requestLocationUpdates",
        "getLastLocation",
    ],
    "android.permission.CAMERA": [
        "open",
        "openCamera",
        "takePicture",
        "startPreview",
    ],
    "android.permission.RECORD_AUDIO": [
        "startRecording",
        "AudioRecord",
        "MediaRecorder",
    ],
    "android.permission.READ_CONTACTS": [
        "query",
        "ContactsContract",
    ],
    "android.permission.WRITE_CONTACTS": [
        "insert",
        "update",
        "delete",
        "ContactsContract",
    ],
    "android.permission.READ_CALL_LOG": [
        "CallLog",
    ],
    "android.permission.WRITE_CALL_LOG": [
        "CallLog",
    ],
    "android.permission.READ_SMS": [
        "Telephony",
        "SmsMessage",
    ],
    "android.permission.SEND_SMS": [
        "sendTextMessage",
        "sendMultipartTextMessage",
        "SmsManager",
    ],
    "android.permission.READ_EXTERNAL_STORAGE": [
        "openFileInput",
        "getExternalStorageDirectory",
        "getExternalFilesDir",
        "MediaStore",
    ],
    "android.permission.WRITE_EXTERNAL_STORAGE": [
        "openFileOutput",
        "getExternalStorageDirectory",
        "getExternalFilesDir",
    ],
    "android.permission.GET_ACCOUNTS": [
        "getAccounts",
        "AccountManager",
    ],
    "android.permission.USE_BIOMETRIC": [
        "BiometricPrompt",
        "authenticate",
    ],
    "android.permission.USE_FINGERPRINT": [
        "FingerprintManager",
        "authenticate",
    ],
    "android.permission.BLUETOOTH_SCAN": [
        "startScan",
        "BluetoothLeScanner",
    ],
    "android.permission.BLUETOOTH_CONNECT": [
        "connectGatt",
        "BluetoothDevice",
    ],
    "android.permission.PROCESS_OUTGOING_CALLS": [
        "android.intent.action.NEW_OUTGOING_CALL",
    ],
    "android.permission.READ_PHONE_STATE": [
        "getDeviceId",
        "getImei",
        "getLine1Number",
        "TelephonyManager",
    ],
}

DANGEROUS_PERMISSIONS = set(PERMISSION_API_MAP.keys())
 
 
def collect_declared_permissions(apk: APK) -> set[str]:
    """Return the set of dangerous permissions declared in the manifest."""
    declared = set()
    for perm in apk.get_permissions():
        if perm in DANGEROUS_PERMISSIONS:
            declared.add(perm)
    return declared
 
 
def collect_all_strings_from_dex(dex_bytes: bytes) -> set[str]:
    """
    Pull every string constant from a DEX file. This is a fast, cheap way
    to check whether an API method name appears *anywhere* in the bytecode
    without having to disassemble every method.
    """
    d = DEX(dex_bytes)
    strings = set()
    for s in d.get_strings():
        strings.add(str(s))
    return strings
 
 
def collect_invoked_methods_from_dex(dex_bytes: bytes) -> set[str]:
    """
    Walk every method's bytecode and collect the targets of all invoke-*
    instructions. Returns a flat set of method-reference strings like
    'Landroid/location/LocationManager;->getLastKnownLocation(...)'.
    """
    d = DEX(dex_bytes)
    invocations: set[str] = set()
    for cls in d.get_classes():
        for method in cls.get_methods():
            try:
                code = method.get_code()
                if code is None:
                    continue
                for ins in code.get_bc().get_instructions():
                    op = ins.get_name()
                    if not op.startswith("invoke"):
                        continue
                    out = ins.get_output() or ""
                    invocations.add(out)
            except Exception:
                continue
    return invocations
 
 
def permission_is_used(
    permission: str,
    invocations: set[str],
    dex_strings: set[str],
) -> bool:
    """
    Return True if any of the API indicators for `permission` appear in
    the app's bytecode (either as an invoked method or as a string constant,
    which covers reflective calls and intent actions).
    """
    indicators = PERMISSION_API_MAP.get(permission, [])
    for indicator in indicators:
        if any(indicator in inv for inv in invocations):
            return True
        if any(indicator in s for s in dex_strings):
            return True
    return False
 
 
def scan_apk(apk_path: Path) -> list[dict]:
    apk = APK(str(apk_path))
 
    declared = collect_declared_permissions(apk)
    if not declared:
        return []
 
    all_invocations: set[str] = set()
    all_strings: set[str] = set()
    for dex_bytes in apk.get_all_dex():
        all_invocations |= collect_invoked_methods_from_dex(dex_bytes)
        all_strings |= collect_all_strings_from_dex(dex_bytes)
 
    issues = []
    for perm in sorted(declared):
        if not permission_is_used(perm, all_invocations, all_strings):
            issues.append({
                "issue": "declared but unused permission",
                "context": {
                    "permission": perm,
                },
                "details": {
                    "reason": (
                        "Permission is listed in the manifest but no matching "
                        "API call or string reference was found in the DEX bytecode."
                    ),
                    "indicators_checked": PERMISSION_API_MAP.get(perm, []),
                },
            })
 
    return issues
 
 
def write_report(app_name: str, issues: list[dict]) -> Path | None:
    if not issues:
        return None
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_DIR / f"{app_name}_permissions_report.jsonl"
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
                print(f"[FLAGGED] {app_name}: {len(issues)} unused permission(s) -> {report_path}")
            else:
                print(f"[OK]      {app_name}")
        except Exception as e:
            print(f"[ERROR]   {app_name}: {e}")
 
    print(f"\nDone. {flagged_apps}/{len(apk_files)} apps flagged, {total_issues} total unused permissions.")
 
 
if __name__ == "__main__":
    main()