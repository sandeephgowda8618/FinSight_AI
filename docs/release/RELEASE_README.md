# FinSight AI release bundle

This bundle is built by `.github/workflows/ci.yml` after the frontend build, backend dependency/migration/tests, and repository hygiene jobs pass. It is an application package, not a deployment. The repository has no approved hosting target or production environment configured.

## Identify and verify a release

CI archives are named `finsight-<version>-<12-character-commit-prefix>.tar.gz`. A local bundle without a source commit is named by version and records a null commit SHA; do not promote such a worktree package as a committed release. `RELEASE-METADATA.json` records the version, full Git commit SHA when available, application entry points, and included migration names. A sibling `.build-info.json` records the UTC packaging timestamp and archive checksum; the `.sha256` file contains the checksum independently. Verify before extracting:

```sh
sha256sum --check finsight-<version>-<12-character-commit-prefix>.tar.gz.sha256
tar -tzf finsight-<version>-<12-character-commit-prefix>.tar.gz
```

On macOS, use `shasum -a 256` and compare its output with the `.sha256` file.

## Configure and start

Extract the verified archive into a new, versioned release directory. Install a supported Node.js 22 runtime and Python 3.12 runtime. Configure the frontend process with `API_BASE_URL=https://<api-origin>` and the backend process with `DATABASE_URL`, `WEB_ORIGIN`, `SESSION_TTL_MINUTES`, `COOKIE_SECURE=true`, `APP_ENV=production`, `AUTH_THROTTLE_SECRET`, `AUTH_LOGIN_MAX_FAILURES`, `AUTH_LOGIN_WINDOW_SECONDS`, and `AUTH_LOGIN_BLOCK_SECONDS`. Generate a unique random `AUTH_THROTTLE_SECRET` of at least 32 bytes and keep it in the deployment secret manager. Rotating this secret changes throttle identifiers and makes existing throttle buckets inaccessible. Values containing credentials belong only in the deployment secret manager. Set the web origin exactly to the browser-facing frontend origin; terminate TLS at an approved proxy/load balancer and forward HTTPS safely.

For the frontend, from the extracted bundle root:

```sh
cd frontend
HOSTNAME=0.0.0.0 PORT=3000 node server.js
```

For the backend, from the extracted bundle root, create a virtual environment and install the bundled pinned runtime requirements:

```sh
cd backend
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.lock
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Run database migrations as a separate, explicitly approved deployment step with a migration-owner role. The bundle includes the current versioned migration under `backend/migrations`; it does not include or apply the supplied target schema wholesale. Use a separate least-privileged application database role at runtime.

## Promotion and rollback

Retain each verified archive, checksum, metadata, migration result, smoke-test report, and deployment record. Promote the same versioned bundle through environments; configure `API_BASE_URL` and backend settings per environment at runtime. Record which artifact version and full commit SHA is active.

To roll back application code, stop the affected processes and point the deployment supervisor to the previous known-good versioned release directory by its metadata version and commit SHA. Verify its checksum before reuse, start it with the appropriate environment configuration, then run the deployment's readiness and authentication smoke checks. Keep the database at its current migrated version unless the migration has a reviewed, tested, explicitly approved down migration. Do not restore an older application against a schema it cannot safely read.

Database migration policy for safe application rollback:

1. Prefer additive expand migrations that preserve existing columns/records and remain compatible with both old and new application versions.
2. Deploy code that can operate with both schema shapes before any contract/removal migration.
3. Delay destructive or incompatible schema changes to a separately reviewed maintenance window after backup and restore validation; document a forward-fix or recovery strategy and owner.
4. Never run the optional trading schema in Release 1. Never automatically reverse a migration as part of application rollback.

## Deployment prerequisite

Before deployment is automated, the deployment owner must choose the hosting target and staging/production topology, configure protected environments and secret references, establish TLS and database network policy, define migration ownership, backups/RTO/RPO, monitoring/readiness, and approval gates. No deployment target or credentials are configured by this repository task. No deployment has been performed.

## MFA production readiness limitation

The current MFA secret-store selector deliberately rejects `APP_ENV=production`
because no production secret-store provider is configured. The fake backend is
for tests only, and the encrypted file backend is development-only. Do not
enable or rely on MFA in a production deployment until an approved production
secret-store provider is implemented, configured, and tested. A passing local
API test suite does not establish production MFA readiness. This limitation
must be resolved before claiming production-ready MFA support.
