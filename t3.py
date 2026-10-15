"""Local command-line entry point: python t3.py inspect example.com --active."""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "T3-Phishing-Detection"))
from t3core import InvalidTarget, inspect_url
from t3core.compare import compare_reports, load_report


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    cli = argparse.ArgumentParser(
        description="Collect URL/domain evidence without a safe/unsafe score."
    )
    commands = cli.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect", help="inspect a URL or domain")
    inspect.add_argument("url")
    inspect.add_argument(
        "--active",
        action="store_true",
        help="contact the target for DNS, TLS, redirect and bounded HTML evidence",
    )
    inspect.add_argument(
        "--threat-lookup",
        action="store_true",
        help="send the full URL to Google; requires SAFE_BROWSING_API_KEY",
    )
    inspect.add_argument("--json", action="store_true", help="write the complete report to stdout")
    inspect.add_argument("--output", type=Path, help="save JSON to a new file")
    compare = commands.add_parser(
        "compare", help="compare two saved reports without network access"
    )
    compare.add_argument("before", type=Path)
    compare.add_argument("after", type=Path)
    args = cli.parse_args()
    if args.command == "compare":
        try:
            before, before_hash = load_report(args.before)
            after, after_hash = load_report(args.after)
            result = compare_reports(before, after)
            result.update(before_file_sha256=before_hash, after_file_sha256=after_hash)
        except (ValueError, KeyError, TypeError, OSError, RecursionError) as error:
            cli.exit(2, f"Cannot compare reports: {error}\n")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    try:
        report = asyncio.run(
            inspect_url(
                args.url,
                active=args.active,
                threat_lookup=args.threat_lookup,
                api_key=os.getenv("SAFE_BROWSING_API_KEY", ""),
            )
        )
    except InvalidTarget as error:
        cli.exit(2, f"Invalid target: {error}\n")
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        try:
            with args.output.open("x", encoding="utf-8") as destination:
                destination.write(encoded)
        except OSError as error:
            cli.exit(2, f"Cannot save report: {error}\n")
    if args.json:
        print(encoded, end="")
    else:
        print(f"T3  {report['target']['url']}")
        print(
            f"Host: {report['target']['host']} | Registered: {report['target']['registrable_domain'] or 'not determined'}"
        )
        for item in report["evidence"]:
            print(f"  {item['status']:20} {item['id']:15} {item['note']}")
        for item in report["findings"]:
            print(f"  Finding: {item['kind']} — {item['detail']}")
        print(
            f"Conclusion: {report['conclusion']} | Partial: {report['partial']} | {report['duration_ms']} ms"
        )
        print("No evidence of abuse is not proof of safety. Use --json to inspect collected facts.")


if __name__ == "__main__":
    main()
