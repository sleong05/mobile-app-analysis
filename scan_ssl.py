import json
from pathlib import Path

from androguard.core.apk import APK
from androguard.core.dex import DEX


APK_DIRS = [Path("100_apps_a"), Path("99_apks-9_per_category")]
REPORT_DIR = Path("reports/cert_verification")
LOG_PATH = Path("scan_ssl.log")

TRUST_MANAGER_IFACE = "Ljavax/net/ssl/X509TrustManager;"


def class_to_source(class_name: str) -> str:
    """Lcom/foo/Bar; -> com.foo.Bar"""
    if class_name.startswith("L") and class_name.endswith(";"):
        class_name = class_name[1:-1]
    return class_name.replace("/", ".")


def method_signature(method) -> str:
    try:
        cls = class_to_source(method.get_class_name())
        return f"{cls}->{method.get_name()}{method.get_descriptor()}"
    except Exception:
        return str(method)


def get_method_instructions(method):
    try:
        code = method.get_code()
        if code is None:
            return []
        return list(code.get_bc().get_instructions())
    except Exception:
        return []


def dump_method_body(method) -> str:
    """Return the method's full disassembled body as a multiline string."""
    lines = []
    for ins in get_method_instructions(method):
        op = ins.get_name()
        out = (ins.get_output() or "").strip()
        lines.append(f"{op} {out}".strip())
    return "\n".join(lines)


def find_delegate_calls(logic) -> list[str]:
    """
    Find invoke instructions whose target method is checkServerTrusted.
    Returns list of "ClassName->methodName(args)ret" strings.
    """
    delegates = []
    for op, out in logic:
        if not op.startswith("invoke"):
            continue
        # The output of an invoke looks like:
        #   v1, v2, Lcom/foo/Bar;->checkServerTrusted([Ljava/...;)V
        if "->checkServerTrusted" not in out:
            continue
        # Pull out everything from the L...; onwards (the target method ref)
        idx = out.find("L")
        if idx == -1:
            continue
        delegates.append(out[idx:])
    return delegates


def analyze_check_server_trusted(method):
    """
    Returns (verdict, reason, delegates).
    verdict in {"ok", "empty", "no-throw", "throws-non-cert"}.
    delegates is a list of target method refs if it's delegating, else [].
    """
    instructions = get_method_instructions(method)
    if not instructions:
        return "empty", "method has no code", []

    # Drop logging noise so a method that only logs and returns still counts as empty
    logic = []
    for ins in instructions:
        op = ins.get_name()
        out = ins.get_output() or ""
        if "Log;->" in out or "PrintStream;->println" in out:
            continue
        logic.append((op, out))

    if not logic or all(op.startswith("return") for op, _ in logic):
        return "empty", "no validation logic, returns immediately", []

    has_throw = any(op.startswith("throw") for op, _ in logic)
    mentions_cert_exception = any("CertificateException" in out for _, out in logic)
    delegates = find_delegate_calls(logic)

    if delegates:
        return "ok", "delegates to another TrustManager", delegates
    if has_throw and mentions_cert_exception:
        return "ok", "throws CertificateException", []
    if has_throw:
        return "throws-non-cert", "throws non-certificate exception", []
    return "no-throw", "never throws — accepts any certificate", []


def scan_apk(apk_path: Path) -> list[dict]:
    apk = APK(str(apk_path))

    issues = []
    for dex_bytes in apk.get_all_dex():
        d = DEX(dex_bytes)
        for cls in d.get_classes():
            # Quick, cheap check: does this class declare X509TrustManager?
            interfaces = cls.get_interfaces() or []
            if TRUST_MANAGER_IFACE not in interfaces:
                continue

            # Only now do we touch any method bytecode
            for method in cls.get_methods():
                if method.get_name() != "checkServerTrusted":
                    continue

                verdict, reason, _ = analyze_check_server_trusted(method)
                if verdict == "ok":
                    continue

                issues.append({
                    "issue": f"insecure checkServerTrusted ({verdict})",
                    "context": {
                        "class": class_to_source(cls.get_name()),
                        "method": method_signature(method),
                        "body": dump_method_body(method),
                    },
                    "details": {
                        "reason": reason,
                    },
                })
    return issues


def write_report(app_name: str, issues: list[dict]) -> Path | None:
    if not issues:
        return None
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_DIR / f"{app_name}_ssl_report.jsonl"
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