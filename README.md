# FinSight AI

FinSight AI is an AI-powered financial research and analytics platform for market data, source-backed analysis, portfolio analytics, valuation, risk, and reporting. This repository is being built incrementally. It currently provides a Next.js sign-in page and a FastAPI authentication service with PostgreSQL-backed sessions.

## Local prerequisites

- Node.js 20.9 or newer and npm 10 or newer. Node.js 22 LTS is recommended.
- Python 3.12 or newer and `venv`/`pip`.
- PostgreSQL 16 or newer for authentication and sessions.
- macOS, Linux, or Windows with WSL.

Authentication uses a local PostgreSQL database. Ollama and market-data providers are not configured by this story. Do not put real credentials in the repository.

## Configure and start

1. Clone the repository and enter its root directory.
2. Copy `.env.example` to the repository root as `.env`. Set `DATABASE_URL` to a local PostgreSQL database accessible only to your development user and keep it in this ignored file. Copy `apps/web/.env.example` to `apps/web/.env.local`; `API_BASE_URL` configures the browser app's API target at runtime, and the frontend bundle can be promoted unchanged between environments.
3. Create a new development database, then apply only the FIN-13 identity migration:

   ```sh
   set -a; . ./.env; set +a
   createdb finsight
   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f apps/api/migrations/0001_auth_identity.sql
   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f apps/api/migrations/0002_platform_authorization.sql
   ```

   These versioned migrations create the implemented subset of canonical identity and authorization tables. `0002` adds only `platform_admin` and the single explicit `platform.admin` permission; it does not seed workspace roles or grant product-module permissions. Never apply the supplied target schema wholesale to an existing database.

4. In a terminal, install and start the API:

   ```sh
   python3 -m venv .venv
   . .venv/bin/activate
   python -m pip install -r apps/api/requirements.lock
   python -m uvicorn app.main:app --app-dir apps/api --host 127.0.0.1 --port 8000
   ```

   On Windows PowerShell, replace the first two commands with `py -3 -m venv .venv` and `.venv\Scripts\Activate.ps1`; run the remaining API commands unchanged.

5. In a separate terminal, provision accounts from an administrator-controlled shell. This command prompts for the initial password without displaying it; it requires local database access and no public registration endpoint exists:

   ```sh
   cd apps/api
   python -m app.provision_user analyst@example.com "Analyst"
   ```

   Accounts receive no platform permissions by default. Grant platform administrator access only to a trusted operator-selected account with `python -m app.provision_user admin@example.com "Administrator" --platform-admin`. Operator and Standard User are workspace-scoped in the canonical design and remain unavailable until workspace membership is implemented.

6. In a second terminal, install and start the web app:

   ```sh
   cd apps/web
   npm ci
   npm run dev
   ```

7. Open <http://localhost:3000> and sign in with the provisioned account. The API documentation is at <http://127.0.0.1:8000/docs>.

Stop either development server with `Ctrl+C`. The API binds to loopback for local development. In deployed HTTPS environments set `COOKIE_SECURE=true`, configure `WEB_ORIGIN` to the exact frontend origin, and use a TLS-terminating deployment. `SESSION_TTL_MINUTES` controls the session lifetime (1–10080 minutes; default 60).

## Authentication flow and tests

- `POST /auth/login` accepts an email and password, verifies the Argon2id password hash, and sets an opaque `HttpOnly`, `SameSite=Lax` session cookie. Only the SHA-256 digest of the random cookie value is stored in PostgreSQL.
- `GET /auth/me` requires a valid, unrevoked, unexpired session and returns the signed-in user profile. Protected API routes should use the same backend dependency; frontend state is not an authorization boundary.
- Backend routes requiring a capability use `require_permission(permission_key)`. Permissions are resolved from PostgreSQL through the user's platform role; absent roles and unknown permissions deny access with 403. The current migration grants only `platform.admin`; no current product/admin route consumes it. Workspace roles are not assigned globally. `/app/:path*` has a Next.js Proxy cookie-presence redirect for anonymous page requests; it is only a navigation aid, and every API still validates the server-side session and permission.
- `POST /auth/logout` revokes the current database session and clears the cookie. Login errors use the same public message for unknown users and incorrect passwords.
- There is no public registration route. Account creation or password rotation is performed by a trusted local administrator using the provisioning command above.
- Configure `DATABASE_URL` for a disposable development/test database before applying migrations or running integration tests. Install `apps/api/requirements-dev.lock` in the Python environment, then run the layers independently from the repository root:
  - Backend line and branch coverage (unit tests need no database; integration tests require the identity migration): from the repository root, set `DATABASE_URL` to a disposable migrated PostgreSQL database and run `.venv/bin/python -m pytest -q --cov=app --cov-branch --cov-report=term-missing --cov-report=xml:coverage.xml --cov-report=html:htmlcov apps/api/tests`. This writes a machine-readable `coverage.xml` and browsable `htmlcov/index.html`; reports are ignored local build output.
  - Frontend interaction tests: from `apps/web`, run `npm ci`, `npx playwright install chromium`, and `npm run test:ui`. These tests use deterministic API responses.

The current Playwright setup reports interaction results but does not instrument frontend source for line or branch coverage. No frontend percentage is reported until a source-coverage integration is selected and configured.
  - Live browser smoke: with `DATABASE_URL` set to a disposable PostgreSQL database where migrations `0001_auth_identity.sql` and `0002_platform_authorization.sql` have been applied, run `python scripts/run_live_e2e.py` from the repository root. It starts local API/frontend processes, provisions one random synthetic account, tests failed/successful login and logout in Chromium, then deletes the account. Set `FRONTEND_DIR` to a built Next.js standalone directory to exercise a production build; otherwise it runs the development server.
- The browser suite needs Playwright Chromium (`npx playwright install chromium`). PostgreSQL integration and live smoke require the disposable identity schema; tests do not apply migrations to a database automatically.
- For deployed environments, use HTTPS and set `COOKIE_SECURE=true`. Do not use the development HTTP cookie setting outside loopback development.

## Repository layout

```text
apps/
  api/       FastAPI auth API, versioned migration, tests, requirements, and lock
  web/       Next.js application and npm lockfile
Component_diagrams/  Read-only architecture references
Database/            Read-only schema and backlog references
Dcos/                Read-only project documents
```

Current runtime architecture, API contracts, compatibility rules, and ADRs: [Architecture documentation](docs/architecture/README.md).

Authentication is limited to the FIN-13 login/session slice. Password recovery, MFA, role/permission administration, authentication audit events, a health endpoint, broker execution, and financial calculations are outside this slice. Preserve the Release 1 read-only boundary.

## Branches and review

- Keep `main` releasable. Use short-lived branches named `codex/<issue>-<short-description>` or `<issue>-<short-description>`.
- Open a pull request for changes; include the Jira key, scope, test commands and observed results, and any known limitations.
- Request review from another engineer before merging. Do not merge with failing required checks; do not claim CI is configured until a workflow exists and has been verified.
- Keep project source documents read-only. Use `conversation.txt` for questions/decisions and `IMPLEMENTATION_STATUS.txt` for implementation evidence.

## Troubleshooting

- **Port already in use:** stop the other process or choose an unused port and update the corresponding start command and local configuration.
- **Python package installation fails:** confirm Python 3.12+ is active, recreate the virtual environment if it is corrupted, and rerun the install command.
- **Python dependencies change:** update the direct pins in `apps/api/requirements.txt`, install them into a clean virtual environment, then refresh `apps/api/requirements.lock` with `python -m pip freeze > apps/api/requirements.lock`.
- **`npm ci` reports a lockfile mismatch:** use the committed `package-lock.json`; do not replace `npm ci` with an unpinned install in clean setup instructions.
- **Web page cannot reach the API:** confirm the API process is running and `API_BASE_URL` in `apps/web/.env.local` points to its local URL; confirm `WEB_ORIGIN` matches the browser page origin.
- **Login returns a service-unavailable error:** confirm `DATABASE_URL` points to the migrated local database and that PostgreSQL is accepting connections.
- **A session cookie is missing over local HTTP:** confirm `COOKIE_SECURE=false` is set only in the local development `.env`; use `COOKIE_SECURE=true` behind HTTPS in deployed environments.

## Versioned build and deployment

The repository currently has no configured hosting target, deployment credentials, staging environment, or production environment. FIN-74 therefore produces a versioned downloadable build bundle; it does not deploy the application. The existing GitHub Actions workflow builds the standalone Next.js frontend, checks the FastAPI backend against its lock and disposable PostgreSQL tests, and packages both only after the CI jobs pass. CI bundles are named `finsight-<version>-<commit-prefix>.tar.gz` and include `RELEASE-METADATA.json` with version and full commit SHA. A sibling `.build-info.json` records the UTC packaging timestamp and archive checksum; `.sha256` independently verifies the exact archive. A local bundle without a source commit is named by version and records a null commit SHA. Pull-request/main builds use the package version; a `v<semver>` tag uses that tagged version. GitHub Actions retains the package artifact for 90 days.

The bundle contains a Node.js 22 standalone frontend and the FastAPI source, pinned backend runtime lockfile, and versioned migrations. The frontend reads `API_BASE_URL` from the frontend server's runtime environment through `/api/runtime-config`; the value must be an origin such as `https://api.example.com`, without credentials or a path. Backend runtime configuration uses `DATABASE_URL`, `WEB_ORIGIN`, `SESSION_TTL_MINUTES`, `COOKIE_SECURE`, and `APP_ENV`. Supply secrets through the chosen deployment platform's secret manager, never through the bundle or repository. Configure a least-privileged database runtime role separately from the migration role, TLS, backups, readiness/monitoring, and operator-owned RTO/RPO before production use.

Deployment and rollback runbook: [docs/release/RELEASE_README.md](docs/release/RELEASE_README.md). A deployment owner must select and configure the hosting target and protected environments before any deployment workflow can be added. Do not apply `Database/schema_optional_trading.sql`; Release 1 has no broker execution capability.


Requirements and story traceability: [matrix](docs/requirements/traceability-matrix.md), [SRS addendum](docs/requirements/srs-addendum.md), [requirement register](docs/requirements/traceability-requirements.csv), and [story register](docs/requirements/traceability-stories.csv).
