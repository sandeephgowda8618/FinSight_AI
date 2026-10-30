"""Helpers for the stable aggregate GitHub Actions required check."""

from __future__ import annotations

import json
import os
import sys
from typing import Any

REQUIRED_JOBS = (
    "frontend",
    "backend",
    "e2e",
    "hygiene",
    "dependency-security",
    "release-package",
)


def failed_required_jobs(needs: dict[str, Any]) -> list[str]:
    """FN-CI-001: Return required jobs that did not complete successfully."""
    failures = []
    for job in REQUIRED_JOBS:
        result = needs.get(job)
        outcome = result.get("result") if isinstance(result, dict) else None
        if outcome != "success":
            failures.append(f"{job}={outcome or 'missing'}")
    return failures


if __name__ == "__main__":
    try:
        job_results = json.loads(os.environ.get("CI_NEEDS_JSON", "{}"))
    except json.JSONDecodeError as exc:
        print(f"::error::Invalid CI_NEEDS_JSON: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    if not isinstance(job_results, dict):
        print("::error::CI_NEEDS_JSON must contain a JSON object", file=sys.stderr)
        raise SystemExit(2)

    failed = failed_required_jobs(job_results)
    if failed:
        print("::error::Required CI jobs did not succeed: " + ", ".join(failed))
        raise SystemExit(1)

    print("All required CI jobs succeeded.")
