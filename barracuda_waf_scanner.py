#!/usr/bin/env python3
"""
Barracuda WAF Security Testing Scanner
=======================================
Open-source security configuration assessment tool for Barracuda Web Application Firewall.
Connects via REST API to audit policies, SSL/TLS, access controls, logging, and compliance posture.

Usage:
    python barracuda_waf_scanner.py --host <ip> --user admin --password <pass> [options]

Author: Phalanx Cyber
License: MIT
"""

import argparse
import logging
import sys
import os
import yaml
from datetime import datetime

# Ensure package imports work when run from repo root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.api_client import BarracudaWafClient, AuthenticationError
from utils.report_generator import generate_html_report, generate_json_report
from utils.severity import compute_posture_score, score_to_grade, severity_counts, SEVERITY_ORDER
from checks import ALL_CHECKERS

BANNER = r"""
 ____                                     _        __        ___    _____
| __ )  __ _ _ __ _ __ __ _  ___ _   _  __| | __ _  \ \      / / \  |  ___|
|  _ \ / _` | '__| '__/ _` |/ __| | | |/ _` |/ _` |  \ \ /\ / / _ \ | |_
| |_) | (_| | |  | | | (_| | (__| |_| | (_| | (_| |   \ V  V / ___ \|  _|
|____/ \__,_|_|  |_|  \__,_|\___|\__,_|\__,_|\__,_|    \_/\_/_/   \_\_|

    Security Testing Scanner v1.0.0
    https://github.com/Krishcalin/Barracuda-WAF-Security-Testing
"""


def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def load_profile(profile_path):
    """Load scan profile from YAML file."""
    if not profile_path or not os.path.exists(profile_path):
        return None
    with open(profile_path, "r") as f:
        return yaml.safe_load(f)


def get_enabled_checks(args, profile):
    """Determine which check categories to run."""
    if args.checks:
        return [c.strip() for c in args.checks.split(",")]

    if profile and "checks" in profile:
        return [k for k, v in profile["checks"].items() if v]

    return list(ALL_CHECKERS.keys())


def print_summary(findings):
    """Print a colored summary table to the console."""
    counts = severity_counts(findings)
    score = compute_posture_score(findings)
    grade = score_to_grade(score)

    colors = {
        "CRITICAL": "\033[91m",
        "HIGH": "\033[93m",
        "MEDIUM": "\033[33m",
        "LOW": "\033[92m",
        "INFO": "\033[94m",
        "RESET": "\033[0m",
        "BOLD": "\033[1m",
        "WHITE": "\033[97m",
    }

    print(f"\n{colors['BOLD']}{'='*60}")
    print(f"  SCAN RESULTS SUMMARY")
    print(f"{'='*60}{colors['RESET']}\n")

    print(f"  {colors['WHITE']}Total Findings:{colors['RESET']}  {len(findings)}")
    print(f"  {colors['WHITE']}Posture Score:{colors['RESET']}   {score}/100 (Grade {grade})")
    print()

    print(f"  {colors['BOLD']}Severity Breakdown:{colors['RESET']}")
    for sev in SEVERITY_ORDER:
        c = counts.get(sev, 0)
        if c > 0:
            color = colors.get(sev, "")
            print(f"    {color}{sev:10s}{colors['RESET']}  {c}")

    print()

    # Category breakdown
    categories = {}
    for f in findings:
        cat = f.get("category", "Other")
        categories[cat] = categories.get(cat, 0) + 1

    if categories:
        print(f"  {colors['BOLD']}Category Breakdown:{colors['RESET']}")
        for cat, cnt in sorted(categories.items(), key=lambda x: -x[1]):
            print(f"    {cat:30s}  {cnt}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Barracuda WAF Security Testing Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --host 192.168.1.100 --user admin --password MyP@ss
  %(prog)s --host waf.corp.com --port 8443 --user admin --password MyP@ss --html report.html --json report.json
  %(prog)s --host 10.0.0.1 --user admin --password MyP@ss --checks ssl_tls,waf_policies --insecure
  %(prog)s --host 10.0.0.1 --user admin --password MyP@ss --profile config/default_profile.yaml
""",
    )

    conn = parser.add_argument_group("Connection")
    conn.add_argument("--host", required=True, help="Barracuda WAF IP or hostname")
    conn.add_argument("--port", type=int, default=8443, help="REST API port (default: 8443)")
    conn.add_argument("--user", default="admin", help="Admin username (default: admin)")
    conn.add_argument("--password", required=True, help="Admin password")
    conn.add_argument("--insecure", action="store_true", help="Skip SSL certificate verification")
    conn.add_argument("--timeout", type=int, default=30, help="API request timeout in seconds (default: 30)")

    scan = parser.add_argument_group("Scan Options")
    scan.add_argument("--checks", help="Comma-separated list of check categories to run")
    scan.add_argument("--profile", help="Path to YAML scan profile")

    output = parser.add_argument_group("Output")
    output.add_argument("--html", help="Output HTML report path")
    output.add_argument("--json", help="Output JSON report path")
    output.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    output.add_argument("--quiet", "-q", action="store_true", help="Suppress banner and summary")

    args = parser.parse_args()
    setup_logging(args.verbose)
    logger = logging.getLogger("scanner")

    if not args.quiet:
        print(BANNER)

    # Load scan profile
    profile = load_profile(args.profile)

    # Determine which checks to run
    enabled = get_enabled_checks(args, profile)
    logger.info("Enabled check categories: %s", ", ".join(enabled))

    # Connect to WAF
    client = BarracudaWafClient(
        host=args.host,
        port=args.port,
        username=args.user,
        password=args.password,
        verify_ssl=not args.insecure,
        timeout=args.timeout,
    )

    try:
        logger.info("Connecting to Barracuda WAF at %s:%d...", args.host, args.port)
        client.login()
        logger.info("Authentication successful")
    except AuthenticationError as e:
        logger.error("Authentication failed: %s", e)
        sys.exit(1)
    except ConnectionError as e:
        logger.error("Connection failed: %s", e)
        sys.exit(1)

    # Run checks
    all_findings = []
    for check_name in enabled:
        if check_name not in ALL_CHECKERS:
            logger.warning("Unknown check category: %s (skipping)", check_name)
            continue
        checker_cls = ALL_CHECKERS[check_name]
        try:
            checker = checker_cls(client)
            findings = checker.run_all()
            all_findings.extend(findings)
            logger.info("  %s: %d findings", check_name, len(findings))
        except Exception as e:
            logger.error("  %s: error — %s", check_name, e)
            if args.verbose:
                import traceback
                traceback.print_exc()

    # Logout
    client.logout()
    logger.info("Disconnected from WAF")

    # Build metadata
    metadata = {
        "target": f"{args.host}:{args.port}",
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scanner_version": "1.0.0",
        "checks_run": enabled,
        "total_checks_available": len(ALL_CHECKERS),
    }

    # Print summary
    if not args.quiet:
        print_summary(all_findings)

    # Generate reports
    if args.html:
        generate_html_report(all_findings, metadata, args.html)
        logger.info("HTML report saved to: %s", args.html)
        if not args.quiet:
            print(f"  HTML report: {args.html}")

    if args.json:
        generate_json_report(all_findings, metadata, args.json)
        logger.info("JSON report saved to: %s", args.json)
        if not args.quiet:
            print(f"  JSON report: {args.json}")

    if not args.html and not args.json:
        logger.info("No report output specified. Use --html and/or --json to save reports.")

    # Exit code based on findings
    counts = severity_counts(all_findings)
    if counts.get("CRITICAL", 0) > 0:
        sys.exit(2)
    elif counts.get("HIGH", 0) > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
