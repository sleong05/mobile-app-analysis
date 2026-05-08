import json
import re
from pathlib import Path

from androguard.core.apk import APK
from androguard.core.dex import DEX


APK_DIRS = [Path("100_apps_a"), Path("99_apks-9_per_category")]
REPORT_DIR = Path("reports/https_check")

# Regex patterns

# Any http:// URL that is NOT https://
HTTP_URL_RE = re.compile(
    r'http://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
)

# Matches any https:// URL (used to confirm the app does use HTTPS somewhere)
HTTPS_URL_RE = re.compile(
    r'https://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
)

# Noise: localhost / loopback / schema-only / templating placeholders
NOISE_RE = re.compile(
    r'(localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|schemas\.android\.com'
    r'|schemas\.openxmlformats\.org|www\.w3\.org|xmlpull\.org'
    r'|apache\.org/xml|%s|%d|\{\{|\$\{)',
    re.IGNORECASE,
)

# OkHttp / HttpURLConnection / Volley / Retrofit call sites
HTTP_CLIENT_INVOCATIONS = [
    "HttpURLConnection",
    "OkHttpClient",
    "HttpsURLConnection",
    "Volley",
    "Retrofit",
    "CloseableHttpClient",
    "DefaultHttpClient",
    "AndroidHttpClient",
    "openConnection",
    "newCall",
]

# Network-security-config attributes that disable cert / cleartext checks
INSECURE_NSC_PATTERNS = [
    "cleartextTrafficPermitted",     # true = HTTP allowed
    "base-config",                   # catch-all override
    "domain-config",                 # per-domain overrides
    "trust-anchors",                 # custom CA bundle
    "certificates",                  # user/system cert trust
    "pin-set",                       # cert pinning (presence = good, absence = bad)
]

# AndroidManifest flags that weaken transport security
INSECURE_MANIFEST_ATTRS = [
    "android:usesCleartextTraffic",  # true = HTTP allowed app-wide
    "android:networkSecurityConfig", # presence means custom NSC (inspect further)
]


# Helpers

def is_noise(url: str) -> bool:
    return bool(NOISE_RE.search(url))


def collect_dex_strings(dex_bytes: bytes) -> list[str]:
    d = DEX(dex_bytes)
    return [str(s) for s in d.get_strings()]


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

# Per layer checks

def check_manifest(apk: APK) -> list[dict]:
    """
    Inspect AndroidManifest.xml for cleartext traffic flags and NSC references.
    """
    issues = []
    manifest_xml = apk.get_android_manifest_xml()
    if manifest_xml is None:
        return issues

    manifest_str = str(manifest_xml)

    if "android:usesCleartextTraffic" in manifest_str:
        # androguard exposes this as a parsed attribute too
        app_el = manifest_xml.find(".//application")
        val = (app_el.get("{http://schemas.android.com/apk/res/android}usesCleartextTraffic")
               if app_el is not None else None)
        if val and val.lower() == "true":
            issues.append({
                "issue": "cleartext traffic enabled in manifest",
                "layer": "manifest",
                "context": {"attribute": "android:usesCleartextTraffic", "value": "true"},
                "details": {"reason": "App explicitly allows HTTP traffic app-wide."},
            })

    if "networkSecurityConfig" in manifest_str:
        issues.append({
            "issue": "custom network security config present",
            "layer": "manifest",
            "context": {"attribute": "android:networkSecurityConfig"},
            "details": {"reason": "App uses a custom NSC — inspect res/xml/ for cleartext or weak-trust rules."},
        })

    return issues


def check_network_security_config(apk: APK) -> list[dict]:
    """
    Parse the network_security_config XML resource for insecure settings.
    """
    issues = []
    # androguard exposes raw files; NSC lives at res/xml/network_security_config.xml
    # (or whatever name the manifest references, but this covers 99% of apps)
    for fname in apk.get_files():
        if not fname.startswith("res/xml/") or not fname.endswith(".xml"):
            continue
        try:
            raw = apk.get_file(fname).decode("utf-8", errors="replace")
        except Exception:
            continue

        if "cleartextTrafficPermitted" in raw and 'cleartextTrafficPermitted="true"' in raw:
            issues.append({
                "issue": "NSC allows cleartext traffic",
                "layer": "network_security_config",
                "context": {"file": fname},
                "details": {
                    "reason": "cleartextTrafficPermitted=\"true\" found — HTTP is explicitly allowed.",
                    "snippet": _extract_snippet(raw, "cleartextTrafficPermitted"),
                },
            })

        if "<base-config" in raw and "cleartextTrafficPermitted" not in raw:
            # base-config without explicit cleartextTrafficPermitted defaults to
            # true on API < 28, false on API >= 28.  Flag for review.
            issues.append({
                "issue": "NSC base-config without explicit cleartext flag",
                "layer": "network_security_config",
                "context": {"file": fname},
                "details": {
                    "reason": "base-config present but cleartextTrafficPermitted not set; "
                              "may allow HTTP on pre-API-28 devices.",
                },
            })

        if "user" in raw and "<certificates" in raw:
            issues.append({
                "issue": "NSC trusts user-installed certificates",
                "layer": "network_security_config",
                "context": {"file": fname},
                "details": {
                    "reason": "User CA trust enables MITM attacks via installed certificates.",
                    "snippet": _extract_snippet(raw, "<certificates"),
                },
            })

    return issues


def check_hardcoded_http_urls(dex_strings: list[str]) -> list[dict]:
    """
    Scan DEX string constants for hardcoded http:// URLs.
    """
    seen: set[str] = set()
    issues = []
    for s in dex_strings:
        for match in HTTP_URL_RE.finditer(s):
            url = match.group()
            if is_noise(url) or url in seen:
                continue
            seen.add(url)
            issues.append({
                "issue": "hardcoded HTTP URL in bytecode",
                "layer": "dex_strings",
                "context": {"url": url},
                "details": {
                    "reason": "Plaintext HTTP endpoint found as a string constant.",
                },
            })
    return issues


def check_mixed_content(dex_strings: list[str]) -> list[dict]:
    """
    Detect mixed content: app uses HTTPS somewhere but also has HTTP URLs,
    which are likely API endpoints rather than documentation links.
    """
    http_urls = {
        m.group()
        for s in dex_strings
        for m in HTTP_URL_RE.finditer(s)
        if not is_noise(m.group())
    }
    https_urls = {
        m.group()
        for s in dex_strings
        for m in HTTPS_URL_RE.finditer(s)
        if not is_noise(m.group())
    }

    if http_urls and https_urls:
        return [{
            "issue": "mixed HTTP and HTTPS usage",
            "layer": "dex_strings",
            "context": {
                "http_count": len(http_urls),
                "https_count": len(https_urls),
                "http_sample": sorted(http_urls)[:5],
            },
            "details": {
                "reason": "App uses HTTPS for some endpoints but falls back to HTTP for others.",
            },
        }]
    return []


def check_http_client_usage(invocations: list[str]) -> list[dict]:
    """
    Look for HTTP client invocations that suggest dynamic URL construction
    (i.e. the URL may not appear as a string literal but HTTP could still be used).
    """
    found: dict[str, int] = {}
    for inv in invocations:
        for client in HTTP_CLIENT_INVOCATIONS:
            if client in inv:
                found[client] = found.get(client, 0) + 1

    if not found:
        return []

    return [{
        "issue": "HTTP client APIs in use",
        "layer": "dex_invocations",
        "context": {"clients_found": found},
        "details": {
            "reason": "HTTP client classes invoked — verify URLs are HTTPS if not caught by string scan.",
        },
    }]


def check_socket_usage(invocations: list[str]) -> list[dict]:
    """
    Flag raw Socket usage — raw TCP sockets bypass HTTPS entirely.
    """
    socket_hits = [inv for inv in invocations if "Socket" in inv and "SSL" not in inv]
    if not socket_hits:
        return []

    sample = list(dict.fromkeys(socket_hits))[:5]   # deduplicated sample
    return [{
        "issue": "raw (non-SSL) socket usage",
        "layer": "dex_invocations",
        "context": {"sample_invocations": sample},
        "details": {
            "reason": "Plain Socket invocations found — raw TCP has no transport encryption.",
        },
    }]

# Utility

def _extract_snippet(text: str, keyword: str, context_chars: int = 120) -> str:
    idx = text.find(keyword)
    if idx == -1:
        return ""
    start = max(0, idx - 40)
    end = min(len(text), idx + context_chars)
    return text[start:end].strip()


# Orchestration

def scan_apk(apk_path: Path) -> list[dict]:
    apk = APK(str(apk_path))

    all_strings: list[str] = []
    all_invocations: list[str] = []
    for dex_bytes in apk.get_all_dex():
        all_strings.extend(collect_dex_strings(dex_bytes))
        all_invocations.extend(collect_invoked_methods(dex_bytes))

    issues: list[dict] = []
    issues.extend(check_manifest(apk))
    issues.extend(check_network_security_config(apk))
    issues.extend(check_hardcoded_http_urls(all_strings))
    issues.extend(check_mixed_content(all_strings))
    issues.extend(check_http_client_usage(all_invocations))
    issues.extend(check_socket_usage(all_invocations))

    return issues


def write_report(app_name: str, issues: list[dict]) -> Path | None:
    if not issues:
        return None
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_DIR / f"{app_name}_https_report.jsonl"
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