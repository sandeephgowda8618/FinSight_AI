# FinSight AI — Defect Triage and Regression Traceability Registry

**Document version:** 1.0.0
**Release baseline:** 0.1.0
**Traceability:** NFR-G-27 (Dependency Management), NFR-G-38 (Deployment Reproducibility), FIN-81 / FS-11-10
**Classification:** Internal Engineering Record

---

## 1. Overview & Operating Policy

This defect registry tracks defects, edge cases, and regressions discovered during Sprint 1 development and continuous integration hardening.

In accordance with FinSight AI engineering rules:
1. Every resolved defect must link to an automated regression test.
2. Regression tests must execute in CI before merging pull requests.
3. Defect fixes must not weaken security posture, alter the read-only Release 1 boundary, or bypass input validation.

---

## 2. Defect Traceability Matrix

| Defect ID | Title | Severity | Status | Associated Story | Regression Test Reference |
| :--- | :--- | :--- | :--- | :--- | :--- |
| DEF-001 | Unvalidated input error handling in authentication endpoint | High | VERIFIED | FIN-13 / FS-01-01 | apps/api/tests/test_auth_unit.py::test_login_rejects_invalid_input_before_database_access |
| DEF-002 | Authentication failure throttling threshold race condition | High | VERIFIED | FIN-14 / FS-01-03 | apps/api/tests/test_throttle.py::test_record_failure_blocks_on_first_failure_when_threshold_is_one |
| DEF-003 | Identity schema duplicate email and cascade constraints | High | VERIFIED | FIN-13 / FS-01-01 | apps/api/tests/test_identity_constraints.py::test_identity_schema_rejects_duplicate_email_and_cascades_sessions |
| DEF-004 | Session cookie replay vulnerability after logout | Critical | VERIFIED | FIN-13 / FS-01-01 | apps/api/tests/test_auth.py::test_logout_revokes_session_and_replay_fails |
| DEF-005 | CI aggregate quality gate silently passing on skipped or missing jobs | Critical | VERIFIED | FIN-73 / FS-11-02 | apps/api/tests/test_ci_gate.py::test_missing_required_job_fails_the_aggregate |

---

## 3. Defect Details and Resolutions

### DEF-001: Unvalidated input error handling in authentication endpoint
- **Severity:** High
- **Component:** Backend Authentication Service (`apps/api/app/main.py`)
- **Symptoms:** Malformed credentials could trigger unexpected internal exceptions before boundary validation.
- **Root Cause:** Direct dictionary access on unvalidated payloads prior to Pydantic schema validation.
- **Resolution:** Enforced strict Pydantic model parsing and custom exception handlers returning standard 422 JSON envelopes.
- **Regression Test:** `apps/api/tests/test_auth_unit.py::test_login_rejects_invalid_input_before_database_access`
- **Verification Command:** `pytest apps/api/tests/test_auth_unit.py -k test_login_rejects_invalid_input_before_database_access`

### DEF-002: Authentication failure throttling threshold race condition
- **Severity:** High
- **Component:** Throttling & Lockout Engine (`apps/api/app/throttle.py`)
- **Symptoms:** Fast concurrent requests could exceed configured attempt thresholds without triggering blocking state.
- **Root Cause:** Non-atomic read-modify-write cycle in in-memory throttle cache.
- **Resolution:** Re-architected throttle state update to enforce immediate block evaluation upon threshold attainment.
- **Regression Test:** `apps/api/tests/test_throttle.py::test_record_failure_blocks_on_first_failure_when_threshold_is_one`
- **Verification Command:** `pytest apps/api/tests/test_throttle.py -k test_record_failure_blocks_on_first_failure_when_threshold_is_one`

### DEF-003: Identity schema duplicate email and cascade constraints
- **Severity:** High
- **Component:** Database Migrations (`apps/api/migrations/0001_auth_identity.sql`)
- **Symptoms:** Potential session orphan records when deleting user accounts or duplicate email casing collisions.
- **Root Cause:** Missing `ON DELETE CASCADE` foreign key constraint and non-normalized lowercased unique index.
- **Resolution:** Added explicit `ON DELETE CASCADE` on session foreign keys and lower(email) unique constraint.
- **Regression Test:** `apps/api/tests/test_identity_constraints.py::test_identity_schema_rejects_duplicate_email_and_cascades_sessions`
- **Verification Command:** `pytest apps/api/tests/test_identity_constraints.py -k test_identity_schema_rejects_duplicate_email_and_cascades_sessions`

### DEF-004: Session cookie replay vulnerability after logout
- **Severity:** Critical
- **Component:** Session Revocation Manager (`apps/api/app/auth.py`)
- **Symptoms:** Revoked session cookies could theoretically be replayed if revocation only cleared client cookies without database tombstone.
- **Root Cause:** Client-side cookie expiry was returned without deleting the session hash from the database backend.
- **Resolution:** Guaranteed server-side database session deletion inside an atomic transaction before clearing HTTP cookies.
- **Regression Test:** `apps/api/tests/test_auth.py::test_logout_revokes_session_and_replay_fails`
- **Verification Command:** `pytest apps/api/tests/test_auth.py -k test_logout_revokes_session_and_replay_fails`

### DEF-005: CI aggregate quality gate silently passing on skipped or missing jobs
- **Severity:** Critical
- **Component:** Continuous Integration Quality Gate (`scripts/ci_gate.py`, `.github/workflows/ci.yml`)
- **Symptoms:** If a required prerequisite workflow job was cancelled, skipped, or omitted from the matrix, GitHub Actions could report an aggregate success.
- **Root Cause:** Prerequisite job verification checked only that none had failed, rather than verifying every required job was present and explicitly `success`.
- **Resolution:** Implemented `scripts/ci_gate.py` with strict expected job set matching: any missing, skipped, cancelled, or failed prerequisite halts CI.
- **Regression Test:** `apps/api/tests/test_ci_gate.py::test_missing_required_job_fails_the_aggregate`
- **Verification Command:** `pytest apps/api/tests/test_ci_gate.py -k test_missing_required_job_fails_the_aggregate`
