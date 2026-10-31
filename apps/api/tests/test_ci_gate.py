"""Supplemental local unit coverage for the TC_CI_002 aggregate-gate policy."""

import json
import os
import subprocess
import sys

import pytest

from scripts.ci_gate import REQUIRED_JOBS, failed_required_jobs


def test_all_required_jobs_succeed():
    results = {job: {"result": "success"} for job in REQUIRED_JOBS}

    assert failed_required_jobs(results) == []


@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped"])
def test_non_success_required_job_fails_the_aggregate(result):
    results = {job: {"result": "success"} for job in REQUIRED_JOBS}
    results["backend"] = {"result": result}

    assert failed_required_jobs(results) == [f"backend={result}"]


def test_missing_required_job_fails_the_aggregate():
    results = {job: {"result": "success"} for job in REQUIRED_JOBS}
    del results["dependency-security"]

    assert failed_required_jobs(results) == ["dependency-security=missing"]


def test_malformed_job_result_fails_the_aggregate():
    results = {job: {"result": "success"} for job in REQUIRED_JOBS}
    results["hygiene"] = None

    assert failed_required_jobs(results) == ["hygiene=missing"]


@pytest.mark.parametrize("payload", ["not-json", json.dumps(["not", "an", "object"])])
def test_invalid_cli_payload_exits_with_configuration_error(payload):
    environment = os.environ.copy()
    environment["CI_NEEDS_JSON"] = payload

    result = subprocess.run(
        [sys.executable, "scripts/ci_gate.py"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 2
    assert "CI_NEEDS_JSON" in result.stderr


def test_cli_fails_when_required_job_did_not_succeed():
    outcomes = {job: {"result": "success"} for job in REQUIRED_JOBS}
    outcomes["backend"] = {"result": "failure"}
    environment = os.environ.copy()
    environment["CI_NEEDS_JSON"] = json.dumps(outcomes)

    result = subprocess.run(
        [sys.executable, "scripts/ci_gate.py"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 1
    assert "backend=failure" in result.stdout
