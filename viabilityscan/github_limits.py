"""
GitHub API Rate Limit Guard — hardcoded tier thresholds.
Fails fast *before* hitting GitHub's actual rate limits.

Thresholds mirror free-tier limits from https://api.github.com/rate_limit.
Set FAIL_AT_PCT to control how aggressively we bail out.
"""

import os
import sys
import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional

# ── Hardcoded free-tier limits ──────────────────────────────────────────────
# These match the actual GitHub free-plan limits. Adjust if you upgrade.
FREE_TIER_LIMITS: dict[str, int] = {
    "core":                        5000,   # per hour
    "search":                      30,     # per minute
    "graphql":                     5000,   # per hour
    "code_search":                 10,     # per minute
    "code_scanning_upload":        5000,   # per hour
    "code_scanning_autofix":       10,     # per hour
    "dependency_sbom":             100,    # per hour
    "dependency_snapshots":        100,    # per hour
    "source_import":               100,    # per hour
    "actions_runner_registration": 10000,  # per hour
}

# Fail when remaining drops below this percentage of the limit.
# 0.10 = fail when 90% used (10% remaining). Tweak to be more/less aggressive.
FAIL_AT_PCT: float = float(os.environ.get("GITHUB_FAIL_AT_PCT", "0.10"))

# Resources we actually care about (skip noise like SCIM, audit_log)
WATCH_RESOURCES: tuple[str, ...] = (
    "core",
    "search",
    "graphql",
    "code_scanning_upload",
)


@dataclass
class RateLimitStatus:
    resource: str
    limit: int
    remaining: int
    used: int
    reset: int          # unix epoch
    fail_threshold: int  # remaining below this = FAIL

    @property
    def pct_used(self) -> float:
        return self.used / self.limit if self.limit > 0 else 0.0

    @property
    def exhausted(self) -> bool:
        return self.remaining <= self.fail_threshold


@dataclass
class RateLimitReport:
    ok: bool = True
    failures: list[str] = field(default_factory=list)
    statuses: dict[str, RateLimitStatus] = field(default_factory=dict)
    raw: Optional[dict] = None


def _fetch_rate_limits(token: Optional[str] = None) -> dict:
    """Fetch live rate limit state from GitHub API."""
    url = "https://api.github.com/rate_limit"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "ViabilityScan/1.0")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        raise RuntimeError(f"GitHub API returned {e.code}: {body[:200]}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Cannot reach GitHub API: {e.reason}")


def check_rate_limits(token: Optional[str] = None) -> RateLimitReport:
    """
    Fetch live rate limits and fail if any watched resource is below threshold.

    Returns RateLimitReport with .ok = False if limits are too close.
    Callers should abort / delay when .ok is False.
    """
    report = RateLimitReport()

    try:
        data = _fetch_rate_limits(token)
    except RuntimeError as e:
        report.ok = False
        report.failures.append(str(e))
        return report

    report.raw = data
    resources = data.get("resources", {})

    for name in WATCH_RESOURCES:
        r = resources.get(name, {})
        limit = r.get("limit", 0) or FREE_TIER_LIMITS.get(name, 0)
        remaining = r.get("remaining", 0)
        used = r.get("used", 0)
        reset = r.get("reset", 0)

        # Skip resources with no limit (not applicable for this auth level)
        if limit == 0:
            continue

        fail_at = max(1, int(limit * FAIL_AT_PCT))
        status = RateLimitStatus(
            resource=name,
            limit=limit,
            remaining=remaining,
            used=used,
            reset=reset,
            fail_threshold=fail_at,
        )
        report.statuses[name] = status

        if status.exhausted:
            report.ok = False
            report.failures.append(
                f"{name}: {remaining}/{limit} remaining "
                f"({status.pct_used:.0%} used, threshold={fail_at})"
            )

    return report


def enforce_or_die(token: Optional[str] = None):
    """
    CLI-friendly: fetch limits, print summary, exit 1 if any are exhausted.

    Intended as a pre-flight check before any batch GitHub operation.
    """
    report = check_rate_limits(token)

    # Print summary table
    print("\nGitHub API Rate Limits")
    print(f"{'Resource':<28} {'Limit':>8} {'Used':>6} {'Rem':>6} {'Pct':>6}  Status")
    print("-" * 70)
    for name in WATCH_RESOURCES:
        s = report.statuses.get(name)
        if s:
            flag = "❌ EXHAUSTED" if s.exhausted else "✅ OK"
            print(f"  {name:<26} {s.limit:>8} {s.used:>6} {s.remaining:>6} {s.pct_used:>5.0%}  {flag}")
        else:
            print(f"  {name:<26} {'—':>8} {'—':>6} {'—':>6} {'—':>6}  ⚠️  unknown")

    if report.failures:
        print(f"\n❌ RATE LIMIT BLOCK — aborting to avoid GitHub 403/429.")
        for f in report.failures:
            print(f"   • {f}")
        sys.exit(1)

    print("✅ All watched resources within safe limits.\n")


if __name__ == "__main__":
    enforce_or_die(token=os.environ.get("GITHUB_TOKEN"))