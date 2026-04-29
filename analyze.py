"""
LLM analyzer for scanner reports. Uses Groq (Llama 3.3 70B).

Usage:
    python analyze.py ssl
    python analyze.py permission

To add a new scanner: create prompts/<name>.py with REPORT_DIR (Path),
GLOB (str), and build_prompt(issue: dict) -> str.

Output:
    - parallel *_analyzed.jsonl files under ai_analysis/
    - analyze.log with per-issue errors and unknown responses
    - prints summary at the end
"""

import importlib
import json
import logging
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv
from groq import Groq, RateLimitError

load_dotenv()

MODEL = "llama-3.3-70b-versatile"
SECONDS_BETWEEN_CALLS = 2  # 30 RPM = 1 every 2s
MAX_OUTPUT_TOKENS = 10
LOG_PATH = Path("analyze.log")

logging.basicConfig(
    filename=LOG_PATH,
    filemode="w",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("analyze")


class RateLimited(Exception):
    pass


def load_scanner(name: str):
    try:
        mod = importlib.import_module(f"prompts.{name}")
    except ImportError as e:
        sys.exit(f"error: no prompts/{name}.py ({e})")
    for attr in ("REPORT_DIR", "GLOB", "build_prompt"):
        if not hasattr(mod, attr):
            sys.exit(f"error: prompts/{name}.py missing '{attr}'")
    return mod


def classify(client, prompt: str) -> bool | None:
    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=MAX_OUTPUT_TOKENS,
        )
        text = (resp.choices[0].message.content or "").strip().lower()
        if text.startswith("true"):
            return True
        if text.startswith("false"):
            return False
        log.warning("unknown response: %r", text)
        return None
    except RateLimitError as e:
        raise RateLimited(str(e))
    except Exception as e:
        log.exception("api error: %s", e)
        return None


def analyze_report(report_path: Path, scanner, client) -> list[dict] | None:
    rel = report_path.relative_to(scanner.REPORT_DIR)
    out_path = (Path("ai_analysis") / scanner.REPORT_DIR.name / rel).with_name(
        rel.stem + "_analyzed.jsonl"
    )
    if out_path.exists():
        with open(out_path, "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    with open(report_path, "r", encoding="utf-8") as f:
        issues = [json.loads(line) for line in f if line.strip()]
    if not issues:
        return None

    completed = []
    for issue in issues:
        issue["true_positive"] = classify(client, scanner.build_prompt(issue))
        completed.append(issue)
        time.sleep(SECONDS_BETWEEN_CALLS)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for issue in completed:
            f.write(json.dumps(issue) + "\n")
    return completed


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: python analyze.py <scanner_name>")

    scanner = load_scanner(sys.argv[1])
    client = Groq(api_key=os.environ["GROQ_API_KEY"])

    reports = sorted(p for p in Path(scanner.REPORT_DIR).glob(scanner.GLOB)
                     if not p.stem.endswith("_analyzed"))
    if not reports:
        sys.exit(f"no reports matching {scanner.GLOB} in {scanner.REPORT_DIR}")

    log.info("analyzing %d %s reports with %s", len(reports), sys.argv[1], MODEL)

    total = true_pos = false_pos = unknown = 0
    apps_with_tp = 0
    rate_limited = False

    for report_path in reports:
        try:
            issues = analyze_report(report_path, scanner, client) or []
        except RateLimited as e:
            log.error("rate limited, stopping: %s", e)
            print(f"\nrate limited — stopping. resume with: python analyze.py {sys.argv[1]}")
            rate_limited = True
            break

        app_tp = 0
        for issue in issues:
            total += 1
            v = issue.get("true_positive")
            if v is True:
                true_pos += 1
                app_tp += 1
            elif v is False:
                false_pos += 1
            else:
                unknown += 1
        if app_tp:
            apps_with_tp += 1

    print(f"\nresults for {sys.argv[1]}{' (PARTIAL)' if rate_limited else ''}:")
    print(f"  apps scanned:        {len(reports)}")
    print(f"  apps with true pos:  {apps_with_tp}")
    print(f"  total issues:        {total}")
    print(f"  true positives:      {true_pos}")
    print(f"  false positives:     {false_pos}")
    print(f"  unknown / errors:    {unknown}")


if __name__ == "__main__":
    main()