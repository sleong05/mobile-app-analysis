"""
Summarize LLM-labeled scanner reports.

Usage:
    python report.py ssl
    python report.py permission

Reads ai_analysis/<scanner_dir>/*_analyzed.jsonl, groups findings by
issue type, and prints a true/false/unknown breakdown per issue type
plus an overall total.
"""

import importlib
import json
import sys
from collections import defaultdict
from pathlib import Path


def load_scanner(name: str):
    try:
        return importlib.import_module(f"prompts.{name}")
    except ImportError as e:
        sys.exit(f"error: no prompts/{name}.py ({e})")


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: python report.py <scanner_name>")

    scanner_name = sys.argv[1]
    scanner = load_scanner(scanner_name)

    analyzed_dir = Path("ai_analysis") / Path(scanner.REPORT_DIR).name
    if not analyzed_dir.exists():
        sys.exit(f"no analyzed reports in {analyzed_dir}")

    reports = sorted(analyzed_dir.glob("*_analyzed.jsonl"))
    if not reports:
        sys.exit(f"no *_analyzed.jsonl files in {analyzed_dir}")

    # issue_type -> {"true": n, "false": n, "unknown": n}
    by_issue = defaultdict(lambda: {"true": 0, "false": 0, "unknown": 0})
    total = {"true": 0, "false": 0, "unknown": 0}
    apps_with_findings = 0

    for report_path in reports:
        had_finding = False
        with open(report_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                issue = json.loads(line)
                had_finding = True
                issue_type = issue.get("issue", "<unknown>")
                v = issue.get("true_positive")
                key = "true" if v is True else "false" if v is False else "unknown"
                by_issue[issue_type][key] += 1
                total[key] += 1
        if had_finding:
            apps_with_findings += 1

    print(f"\nresults for {scanner_name}:")
    print(f"  apps with findings: {apps_with_findings} / {len(reports)}")
    print(f"  total findings:     {sum(total.values())}")
    print(f"    true positives:   {total['true']}")
    print(f"    false positives:  {total['false']}")
    print(f"    unknown:          {total['unknown']}")

    print("\nbreakdown by issue type:")
    # sort by total findings descending
    sorted_issues = sorted(
        by_issue.items(),
        key=lambda kv: sum(kv[1].values()),
        reverse=True,
    )
    name_w = max((len(name) for name, _ in sorted_issues), default=20)
    print(f"  {'issue'.ljust(name_w)}  {'true':>5}  {'false':>5}  {'unk':>4}  {'total':>5}")
    print(f"  {'-' * name_w}  {'-' * 5}  {'-' * 5}  {'-' * 4}  {'-' * 5}")
    for issue_type, counts in sorted_issues:
        total_for_issue = sum(counts.values())
        print(
            f"  {issue_type.ljust(name_w)}  "
            f"{counts['true']:>5}  {counts['false']:>5}  "
            f"{counts['unknown']:>4}  {total_for_issue:>5}"
        )


if __name__ == "__main__":
    main()