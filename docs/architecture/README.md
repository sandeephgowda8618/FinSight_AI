# FinSight AI architecture and compatibility

**Scope:** this page describes the implementation currently in the repository, not the full target system in the SRS or technical design. Source references are read-only: `Dcos/FinSight_Software Requirements Specification (SRS).pdf`, `Dcos/FinSight_AI_Technical_Design_and_Implementation_Plan.pdf`, `Dcos/FinSight_AI_Database_Schema_and_ERD_Reference.pdf`, and the FIN-78 entry in the detailed backlog.

## Current status

| Area | Implemented now | Planned or not implemented |
|---|---|---|
| Web | Next.js App Router sign-in page; runtime API-origin endpoint; cookie-based browser requests | Dashboard, research, analytics, settings, and other product areas |
| API | One modular FastAPI application, currently owning login, current-user lookup, and logout | Domain-service modules, public route version prefix, authorization policies beyond the current-user dependency, rate limiting |
| Data | PostgreSQL is authoritative for the implemented identity/session records | The wider target schema, pgvector, market and analysis data, job records |
| Operations | One versioned SQL identity migration; CI quality, test, dependency-security, hygiene, and release-package jobs | Migration runner, configured deployment target, production environment and automated deployment |
| Integrations | None in the current runtime slice | Ollama, embedding/market-data providers, object storage, email/notifications, workers |

Release 1 remains read-only financial research: there are no broker order routes or enabled trading flows. Password recovery, MFA, administrator invitation UI/email, role administration, audit events, and a health endpoint are not implemented. User provisioning is currently a trusted local CLI operation, not a public registration or application invitation flow.

## Runtime and repository boundaries

- `apps/web/`: Next.js/React presentation. `app/page.js` loads runtime configuration, calls the API, and renders sign-in/session state. The browser is not an authorization boundary.
- `apps/api/app/`: FastAPI application and small auth/database modules. `main.py` validates requests, checks request origin, sets/clears cookies, and uses the identity service logic; `auth.py` hashes passwords and creates/digests opaque tokens; `database.py` connects to PostgreSQL.
- `apps/api/migrations/`: versioned PostgreSQL DDL. `0001_auth_identity.sql` creates the current `roles`, `users`, and `auth_sessions` subset. It is intended for a new development/test database and is not a general migration runner or the supplied full target schema.
- `apps/api/tests/` and `apps/web/tests/`: backend unit/integration, Playwright interaction, and live browser smoke tests. Integration and live smoke require disposable PostgreSQL with the identity migration applied.
- `.github/workflows/ci.yml`: frontend lock/install/build and UI tests; backend locked install, migration, compile, unit/integration tests and coverage; browser smoke; hygiene and dependency security; release packaging after prerequisites pass.
- `scripts/`: release packaging and live browser smoke support. `docs/release/RELEASE_README.md` describes the artifact and deployment prerequisite/rollback procedure.

The technical design's domain modules, adapters, workers, and additional deployables are target boundaries, not currently present applications or services. The current backend remains one FastAPI process.

## Request and authentication flow

1. The browser requests `GET /api/runtime-config` from Next.js. The server reads `API_BASE_URL`, validates that it is an HTTP(S) origin without credentials/path/query/fragment, and returns the origin.
2. The browser calls `GET /auth/me` with credentials to restore a session. FastAPI hashes the cookie token and queries PostgreSQL for a live session and active user.
3. Sign-in sends email/password to `POST /auth/login`. The server verifies the Argon2 password hash (or a dummy hash for an unknown/unusable account), inserts only a SHA-256 digest of a newly generated opaque token in `auth_sessions`, and sets the browser cookie.
4. Sign-out calls `POST /auth/logout`; the backend revokes a matching active session and clears the cookie. Authorization for future protected endpoints must be enforced by the backend, not inferred from web UI state.

Cookie name is `finsight_session`; attributes are `HttpOnly`, `SameSite=Lax`, `Path=/`, a max age from `SESSION_TTL_MINUTES`, and `Secure` according to `COOKIE_SECURE` (defaults to true when `APP_ENV=production`, otherwise false). Configure `WEB_ORIGIN` to the exact trusted frontend origin. CORS currently allows that origin, credentials, GET/POST, and `Content-Type`. Requests carrying a different `Origin` receive 403.

## Implemented HTTP contracts

JSON error bodies from FastAPI use `{"detail": ...}`. Pydantic validation errors use FastAPI's structured `detail` array. Do not expose raw exceptions or database details.

| Method and path | Auth | Request | Success | Relevant errors |
|---|---|---|---|---|
| `GET /api/runtime-config` (Next.js) | No | None | `200 {"apiBaseUrl":"https://api.example.test"}` (shape example) | `503 {"detail":"API_BASE_URL is not configured."}`; `500 {"detail":"API_BASE_URL is invalid."}` |
| `POST /auth/login` | No; valid allowed `Origin` if supplied | `{ "email": "analyst@example.test", "password": "…" }`; email validated, password length 1–1024 | `200 {"user_id":"<uuid>","email":"analyst@example.test","display_name":"Analyst"}` plus session cookie | `401 {"detail":"Email or password is incorrect."}` for unknown/incorrect credentials; `403` disallowed origin; `422` invalid body; `503 {"detail":"Authentication service unavailable"}` for PostgreSQL errors |
| `GET /auth/me` | Yes, valid `finsight_session` cookie | None | `200` with the same `UserView` fields | `401 {"detail":"Authentication required"}` for absent/invalid/expired/revoked session; `503` database failure |
| `POST /auth/logout` | Cookie optional; valid allowed `Origin` if supplied | None | `204`, cookie deleted; matching session revoked when present | `403` disallowed origin; `503` if revocation hits a database error |

The API also exposes FastAPI's generated OpenAPI document and interactive `/docs` in the current application. These are development/API inspection endpoints, not additional product capabilities. There is no `/auth/register`, password-reset, invitation, or health route.

## Persistence and configuration ownership

PostgreSQL is the source of truth for the existing identity data. The migration creates `roles` (unique role key and constrained scope), `users` (case-insensitive unique email, status, nullable password hash and role reference), and `auth_sessions` (user FK with cascade, unique token digest, expiry/revocation timestamps). This is only the implemented subset; consult the schema/ERD reference for the canonical broader target entities. No supplied full schema or optional trading schema is applied by this app.

The current migration is a one-time SQL script with transaction boundaries, not a migration framework. Apply it only to a confirmed new/disposable development or test database, once. Production migration ownership and a general migration runner are unresolved deployment work. Keep application rollback separate from schema rollback; do not reverse a migration automatically. Prefer additive expand/contract migrations and preserve a schema usable by both old and new application versions. Review and test any destructive/contract migration with backup/restore and an explicit recovery owner.

| Variable | Consumer | Meaning and safe baseline |
|---|---|---|
| `DATABASE_URL` | FastAPI | PostgreSQL connection string; required. Keep credentials in ignored local `.env` or an approved secret manager. |
| `WEB_ORIGIN` | FastAPI | Exact allowed browser origin; local example `http://localhost:3000`. |
| `SESSION_TTL_MINUTES` | FastAPI | Idle/session policy input, 1–10080 minutes; default 60. |
| `COOKIE_SECURE` | FastAPI | Explicit cookie Secure switch; production should be true. |
| `APP_ENV` | FastAPI | Environment marker; absent defaults to development for cookie behavior. Set production explicitly in deployment. |
| `API_BASE_URL` | Next.js server | API origin read at runtime; local example `http://localhost:8000`. No credentials or path. |

`.env.example` and `apps/web/.env.example` contain placeholders/examples only. Add new configuration through an explicit variable name, purpose, validation, safe local example, deployment guidance, and tests; never add actual credentials or unsafe production defaults to tracked files.

## Local development and test entry points

Follow the concrete setup in the root `README.md`. In summary, apply the identity migration to a new local database; install backend dependencies from `apps/api/requirements.lock` and run `python -m uvicorn app.main:app --app-dir apps/api --host 127.0.0.1 --port 8000`; install frontend dependencies with `npm ci` under `apps/web` and run `npm run dev`. A trusted operator can provision an account with `python -m app.provision_user EMAIL DISPLAY_NAME` from `apps/api`.

Test entry points documented in the README are backend pytest with coverage, `npm run test:ui`, and `python scripts/run_live_e2e.py`. The latter and PostgreSQL integration tests require a disposable migrated database; browser tests require Playwright Chromium. CI uses locked dependencies and test-only PostgreSQL values.

## Compatibility and change rules

1. **HTTP contracts:** current API paths are unprefixed and have no formal `/v1` policy. Do not claim route versioning already exists. Preserve existing field meaning, status codes, cookie behavior, and generic auth errors. Additive optional response fields are generally safer than renaming/removing fields or changing error/status behavior. For an incompatible contract, first propose/version the public API strategy, document a deprecation window and consumer migration, update OpenAPI/examples and tests, and obtain review before release.
2. **Errors and privacy:** retain stable status classes and JSON `detail` envelope; do not return stack traces, SQL/provider detail, passwords, raw session tokens, or account-existence distinctions. Validation remains 422, authentication 401, origin rejection 403, and unavailable persistence 503 for the current auth slice.
3. **Database:** schema changes must be new versioned migrations; do not edit the reference SQL/PDF or rewrite applied migration history. Validate forward migration on disposable PostgreSQL. Prefer backward-compatible expand/contract; an app rollback does not imply a database downgrade is safe.
4. **Environment:** runtime configuration is separated from code. Validate new settings, document required/optional status and safe defaults, keep real values out of templates/logs, and add ignored local values only to local env files/secret managers.
5. **Dependencies:** exact direct pins and lockfiles are authoritative for installs (`npm ci`, pip lock files). Update manifests and locks together, run consistency/security checks and relevant builds/tests, and review install scripts rather than broadly permitting them.
6. **Artifacts:** release packages carry a version and commit SHA when built from a commit, timestamp/checksum metadata, and a separate checksum. A local artifact with no commit SHA is not a committed release. Promote the same verified artifact; retain previous known-good artifacts for rollback. Deployment is not configured in this repository.
7. **Acceptance:** relevant unit, PostgreSQL integration, frontend interaction and live smoke checks must pass as applicable. CI also checks build, dependency/security and repository hygiene. Do not call GitHub checks passed based on local runs; record unexecuted or infrastructure-blocked checks honestly.

## Architecture Decision Records

- [ADR-0001: Modular Next.js and FastAPI application](adr/0001-modular-nextjs-fastapi.md)
- [ADR-0002: PostgreSQL as structured source of truth](adr/0002-postgresql-source-of-truth.md)
- [ADR-0003: Opaque database-validated sessions](adr/0003-opaque-server-validated-sessions.md)
- [ADR-0004: Versioned migrations and environment configuration](adr/0004-migrations-and-environment-configuration.md)
- [ADR-0005: CI quality and versioned release artifacts](adr/0005-ci-quality-and-release-artifacts.md)

