# Changelog

All notable changes to FinSight AI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Sprint 2 market data ingestion adapters and quantitative analysis services.
- Local LLM inference integration via Ollama adapter interface.
- Read-only financial metric calculation engine.

---

## [0.1.0] - 2026-10-31

### Added
- **Release Management & SBOM (FIN-81 / FS-11-10):**
  - Automated CycloneDX 1.5 JSON Software Bill of Materials (SBOM) generator in `scripts/generate_sbom.py`.
  - Auditable defect triage and regression traceability registry in `docs/release/DEFECT_REGISTRY.md`.
  - Version baseline identification, release bundle packaging with checksums (`.sha256`) and build metadata (`.build-info.json`).
- **CI Quality Gates (FIN-73 / FS-11-02):**
  - Pull request aggregate quality gate (`scripts/ci_gate.py`) requiring positive passage of frontend, backend, e2e, hygiene, dependency-security, and release packaging jobs.
  - Branch protection integration on `main` for `Required quality gates`.
- **Identity & Authentication (FIN-13 / FS-01-01, FIN-16 / FS-01-04):**
  - Argon2id password hashing and constant-time credential comparison.
  - Multi-factor authentication (TOTP) enrollment and verification.
  - HttpOnly secure session cookies and CSRF protection.
- **Login Throttling & Audit Logging (FIN-14 / FS-01-03, FIN-83 / FS-11-12):**
  - Exponential backoff and brute-force throttling on login attempts.
  - Immutable audit event logging for identity and security state transitions.
- **Role-Based Access Control & Isolation (FIN-15 / FS-01-02, FIN-17 / FS-01-05):**
  - Role-based permissions (`admin`, `analyst`, `viewer`).
  - Workspace and user connection scoping with zero cross-tenant leakage.
- **Architecture & API Documentation (FIN-78 / FS-11-07):**
  - OpenAPI 3.1 schema specification and ADR-0006 versioning strategy.
  - Strict input validation models and comprehensive error response schemas.

### Fixed
- **DEF-001:** Resolved Starlette exception handling deprecation warning in HTTP exception middleware (`apps/api/tests/test_auth_unit.py::test_exception_handling_format`).
- **DEF-002:** Addressed concurrent login throttling race condition during rapid credential retry attempts (`apps/api/tests/test_throttle.py::test_login_rate_limiting_threshold`).
- **DEF-003:** Corrected migration ordering and dependency sequence for user connection records (`apps/api/tests/test_identity_constraints.py::test_user_foreign_key_constraints`).
- **DEF-004:** Isolated Playwright browser smoke test contexts to prevent session cross-contamination (`apps/api/tests/test_auth.py::test_session_cookie_revocation_on_logout`).
- **DEF-005:** Fixed CI aggregate gate to explicitly catch skipped or missing prerequisite workflows (`apps/api/tests/test_ci_gate.py::test_missing_required_job_fails_the_aggregate`).

### Security
- Mandated Release 1 read-only financial research boundary (no broker order routes or execution permissions enabled).
- Pinned and locked all backend dependencies (`apps/api/requirements.lock`) and frontend packages (`apps/web/package-lock.json`).
- Automated dependency vulnerability scanning with `npm audit` and `pip-audit`.
