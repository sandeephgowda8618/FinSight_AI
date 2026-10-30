"""Temporary sentinel test for TC_CI_002 negative quality gate verification."""


def test_ci_gate_sentinel_intentional_failure():
    assert False, "CI_GATE_SENTINEL"
