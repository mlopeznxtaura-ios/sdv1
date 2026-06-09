#!/usr/bin/env python3
"""
ViabilityScan CLI — scans a repository for production deployment viability.

Usage:
    viabilityscan scan <repo_path> [--full] [--output report.json] [--ci]
    viabilityscan rate-limits            # check GitHub API rate limits
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from viabilityscan.engine import ViabilityEngine
from viabilityscan.reporter import Reporter
from viabilityscan.github_limits import check_rate_limits, enforce_or_die

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("viabilityscan")


def main():
    parser = argparse.ArgumentParser(
        prog="viabilityscan",
        description="ViabilityScan v1.0 — Repository Deployment Readiness Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  viabilityscan scan .
  viabilityscan scan /path/to/repo --full --output report.json
  viabilityscan scan . --ci              # exits 1 on FAIL (for CI gates)
  viabilityscan rate-limits              # check GitHub API rate limits
  viabilityscan scan . --enforce-limits  # abort if rate limits are too low
        """
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan a repository")
    scan_p.add_argument("repo_path", help="Path to repository root")
    scan_p.add_argument("--full", action="store_true",
                        help="Run all layers (MVP + Semgrep, Trivy, Checkov if installed)")
    scan_p.add_argument("--output", default="viability_report.json",
                        help="Output JSON report path (default: viability_report.json)")
    scan_p.add_argument("--ci", action="store_true",
                        help="CI mode: exit code 1 on FAIL (blocks pipeline)")
    scan_p.add_argument("--enforce-limits", action="store_true",
                        help="Check GitHub rate limits before scan; abort if exhausted")

    limits_p = sub.add_parser("rate-limits", help="Check GitHub API rate limits")

    args = parser.parse_args()

    if args.command == "rate-limits":
        enforce_or_die(token=os.environ.get("GITHUB_TOKEN"))
        return

    if args.command == "scan":
        repo = Path(args.repo_path).resolve()
        if not repo.exists():
            print(f"[ERROR] Path not found: {repo}", file=sys.stderr)
            sys.exit(2)

        # Pre-flight rate limit check (if --enforce-limits)
        if args.enforce_limits:
            report = check_rate_limits(token=os.environ.get("GITHUB_TOKEN"))
            if not report.ok:
                print("\n❌ GitHub rate limits exhausted — aborting scan.", file=sys.stderr)
                for f in report.failures:
                    print(f"   • {f}", file=sys.stderr)
                sys.exit(3)

        print(f"\n{'='*60}")
        print(f"  ViabilityScan v1.0  —  {repo.name}")
        print(f"{'='*60}\n")

        engine = ViabilityEngine(repo, full=args.full)
        result = engine.run()

        reporter = Reporter(result)
        reporter.print_summary()
        reporter.save_json(args.output)

        if args.ci and result["gate"] == "FAIL":
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
