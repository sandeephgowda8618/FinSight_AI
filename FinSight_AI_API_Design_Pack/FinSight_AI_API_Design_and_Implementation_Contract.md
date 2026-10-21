# FinSight AI — API Design & Implementation Contract


**Version:** 1.0-design  |  **Baseline date:** 20 October 2026  |  **Status:** Proposed target contract for developer implementation  |  **Audience:** backend, frontend, data/ML, QA, DevOps/security and reviewers

**Source hierarchy:** Original SRS → canonical SQL/schema and ERD → 72-story Jira backlog/acceptance criteria → four-sprint allocation and Sprint 1 test plan → component diagrams and this contract. This document proposes API contracts; it does not upgrade source implementation/test statuses or approve requirement scope changes.

## Executive decision and guardrails


**Decision A is recommended and incorporated.** Implement one minimal platform-admin-only authorization/capability endpoint in the actual FastAPI app: `GET /api/v1/admin/authorization/capabilities`, protected by the real `require_permission("platform.admin")` dependency. It must return only the caller’s effective permission/capability summary and policy version, not platform user lists or unrelated business resources. The route is a direct test seam for SRS backend RBAC (FR-P1-05/06/07) and Sprint 1 story FS-01-02 / Jira FIN-15; it is not a substitute for implementing authorization across all protected endpoints.

**Release 1 boundary:** historical/read-only financial research and calculations; no broker order, paper-trading execution, broker connection, order/fill/approval or live trading paths in the Release 1 OpenAPI file. FS-07-04 / FIN-54 and FS-08-04 / FIN-60 remain Release 2 only. Do not apply the optional 15-table trading DDL. Internal portfolio ledger transactions are not broker orders and must be explicitly described as such.

**Truthfulness:** the schema reference contains 158 core and 15 optional tables, but is a target-state design; it is not evidence those migrations have been applied. Source RTM records only a scoped subset of behaviors implemented and verified. This contract does not claim that proposed domains/routes exist in the current runtime.

## 1. Source baseline, known runtime and open gaps


| Area | Source-grounded observation | API-design consequence |
| --- | --- | --- |
| Runtime evidenced in addendum | Next.js sign-in/runtime API-origin endpoint; FastAPI login/current-user/logout; PostgreSQL identity/session persistence through a versioned identity migration; CI/test/release-package workflow. | Preserve working auth behavior. Inspect actual app route decorators and cookie/session names before path migration; do not copy the examples here blindly. |
| Known gaps | Password recovery, invitation flow, MFA, role administration/enforcement, auth audit subsystem, health endpoint, document/RAG, market providers, analytics and workers are recorded absent. | These are target contracts, not existing functionality. Build tests and versioned migrations before marking stories done. |
| RBAC decision | RTM marks FR-P1-05/07 as PARTIAL; current identity migration evidence mentions roles but not permission enforcement. | Add canonical permission/role mapping via a new forward-only migration if absent; fail closed if the policy DB is unavailable. |
| Traceability size | RTM records 399 FR/NFR IDs and 10 DIR rules; 72 source story aliases; 54 Sprint 1 test cases and 52 explicit execution rows. | Included CSV traceability preserves source status/test execution independently from proposed endpoint mapping. |
| Planning feasibility | Four-sprint schedule assigns all 72 story/tasks but estimates 251 SP (~62.75 SP/day) and explicitly warns this is not a delivery guarantee. | Use it as backlog/sprint mapping, not an implementation promise. Keep XP/TDD, acceptance evidence and scope gates. |

## 2. Architecture and boundary contracts


| Boundary | Contract |
| --- | --- |
| Client → FastAPI | HTTPS in deployed environments; JSON over REST; streaming only where the deployment’s inference adapter supports it. Never make client-side visibility the security boundary. |
| FastAPI modular monolith | Domain routers call typed service interfaces; services enforce business rules and permissions; repositories parameterize database access. Avoid internal HTTP loopbacks by default. |
| PostgreSQL | Structured source of truth for identity, permissions, snapshots, documents, runs, provenance and outputs. Use canonical SQL names/columns. New schema work uses additive, versioned migrations; never rewrite applied migration history or supplied source SQL. |
| pgvector | Vector search within PostgreSQL deployment in the target design. Embedding model/dimension/chunk/index versions must be compatible. Permission filtering happens before any retrieved text enters model context. |
| Object/file storage | Bytes and exports reside in controlled storage; database records keep metadata/artifact URIs. Downloads require fresh resource/permission checks and short-lived signed links. |
| Background jobs | Durable state in PostgreSQL (`background_jobs`, `job_attempts`, `execution_runs`, `execution_steps`, `execution_events`, and health entities where present); optional queue/cache only dispatches and is not authoritative. |
| Providers / LLM | Market, research, embedding and LLM integrations sit behind interfaces. Keep secret material in a secret manager; store references only. Respect provider coverage, licence and entitlement terms. |
| Future trading extension | Separate Release 2 design/deployment gate. This Release 1 spec intentionally contains no broker/order routes. |

## 3. API conventions


### Base path, identity and headers


Canonical target prefix: `/api/v1`. The existing runtime’s exact auth paths are not fully pinned by the supplied documentation, so first inspect `apps/api/app/main.py` and the auth router, document current paths and session cookie/token format, then either retain them as compatibility aliases or migrate them deliberately with tests. Do not silently break the currently working frontend sign-in flow.

Browser session auth should use Secure, HttpOnly, SameSite cookies and CSRF protections on state-changing requests when cookie-based. If the deployment instead uses bearer tokens, use the selected policy consistently; do not accept ambiguous credentials. Deployed traffic must use HTTPS.

Useful request headers: `X-Request-ID` (optional inbound correlation ID, normalized by the server), `Idempotency-Key` on retryable mutating/job-launch requests, and `If-Match`/resource version for conflict-sensitive updates. Responses carry `request_id` and, where relevant, `correlation_id`. Do not accept user-supplied actor/role claims as authorization proof.

### JSON, validation and response shape


Use Pydantic request/response models with explicit enums, date/timestamp formats, numeric bounds, maximum array/string length and reject-extra behavior where compatible. Separate API DTOs from ORM models. Return only allowlisted fields; never return password hashes, session tokens, API keys, provider secrets or secret-manager contents.

List responses should use deterministic sort order and cursor pagination where suitable. Initial default page size 25, maximum 100. Do not expose unbounded search, histories, arrays, file previews or metric series. Use stable resource IDs and UTC timestamps (ISO 8601). Financial calculation responses disclose currency, method, as-of time, data snapshot, model/configuration version and data limitations.

### HTTP status convention


| Status | Use |
| --- | --- |
| 200 | Successful read/update/action with response body. |
| 201 | Resource created synchronously. |
| 202 | Long-running operation accepted; return job_id and optional run_id. |
| 204 | Successful deletion/logout when no response body is required. |
| 400 | Malformed request or invalid state transition. |
| 401 | Missing, invalid, expired or revoked authentication. |
| 403 | Authenticated but not authorized. |
| 404 | Missing resource or inaccessible resource per anti-enumeration policy. |
| 409 | Idempotency-key payload conflict, version conflict or duplicate/state conflict. |
| 422 | Valid JSON but field/model constraints failed. |
| 429 | Rate limit exceeded; include Retry-After. |
| 503 | Required dependency unavailable; authorization and data integrity checks fail closed. |

### Standard error object


```json
{
  "error": {
    "code": "permission_denied",
    "message": "You do not have permission to perform this action.",
    "field_errors": []
  },
  "request_id": "req_01J...",
  "correlation_id": "corr_01J..."
}
```

Error codes must be stable, client-safe machine values. Suggested codes: `invalid_credentials`, `session_expired`, `permission_denied`, `resource_not_found`, `validation_error`, `conflict`, `idempotency_conflict`, `rate_limited`, `authorization_unavailable`, `dependency_unavailable`, `processing_failed`. Never return raw exception messages, stack traces, SQL, filesystem paths, tokens or secrets.

### Idempotency and concurrency


For mutating requests that can be retried, clients send `Idempotency-Key`. Persist `(actor_id, key, operation, request_hash, status, resource/result reference)` with a unique constraint and a defined retention window. Replaying the same key and same payload returns the prior result; a different payload returns `409 idempotency_conflict`. Worker handlers must also be idempotent. Use optimistic concurrency (resource version / ETag / `If-Match`) for updates to strategies, configs, documents and workspaces.

## 4. Authentication, authorization and decision A


### Default-deny permission model


Authorization has two checks on every protected resource: (1) permission for the requested action, and (2) ownership/workspace membership/resource grant. Permission checks must be performed server-side in the dependency and service/repository layers; query results, exports, document chunks, retrieval traces, jobs and citations receive the same isolation. Do not rely on hidden UI buttons or a platform role name alone.

| Permission family (proposed codes) | Typical operation | Notes |
| --- | --- | --- |
| platform.admin | Inspect platform-level capabilities | Keep the minimal Sprint 1 route read-only. Grant only through explicit role_permissions mapping. |
| platform.roles.read / platform.roles.manage | Read/change platform role permission assignments | Separate read from mutation; immutable audit event required. |
| platform.users.invite / platform.audit.read | Invitation and security audit views | Future functionality requiring SRS-backed route/tests. |
| workspace.read / workspace.manage / workspace.members.manage | Workspace metadata and membership | Check workspace membership and role; prevent privilege escalation/orphaning. |
| documents.read / documents.create / documents.delete / documents.acl.manage | Documents and explicit access grants | Evaluate current grant before metadata/chunk/search/citation; revoke immediately for future retrieval. |
| market.read / market-data.ingest / providers.manage | Market data reads/provider operations | Provider management and ingestion restricted to approved operator capability. |
| analysis.run / valuation.run / risk.run / backtests.run | Analytical calculations and simulations | Tool calls authorize their own inputs and data snapshots. |
| reports.read / reports.export / reports.share | Reports/export/sharing | Fresh permission check both before artifact creation and download. |
| privacy.export / privacy.delete / privacy.credentials.manage | Account privacy and credential lifecycle | Step-up/confirmation and audit where required. |

### Minimal capability endpoint — approved design


#### Observed implementation status — 2026-10-21

The endpoint is implemented in `apps/api/app/main.py` at
`GET /api/v1/admin/authorization/capabilities`. It uses
`require_permission("platform.admin")`.

The observed success response contains:
- `data.subject.user_id`
- `data.subject.platform_role_code`
- `data.effective_permissions`
- `data.capabilities`
- `data.policy_version`
- top-level `request_id` and `correlation_id`

A supplied `request_id` is rejected with HTTP 400 if it exceeds 128 characters
or contains disallowed control characters. Otherwise it is used as the
`correlation_id`; the server generates the canonical `request_id`.

This endpoint's implementation does not mean the full FIN-15 acceptance
criteria are complete. FIN-15 remains PARTIAL. Workspace/resource authorization
remains deferred under the approved platform-only scope.



**GET `/api/v1/admin/authorization/capabilities`**  |  Required permission: `platform.admin`  |  Release: Sprint 1 authorization foundation  |  Must be wired through the real FastAPI dependency chain, not a test-only helper.

Success contract (example):

```json
{
  "data": {
    "subject": {
      "user_id": "<uuid>",
      "platform_role_code": "platform_admin"
    },
    "effective_permissions": [
      "platform.admin",
      "platform.roles.read"
    ],
    "capabilities": [
      "inspect_authorization_policy"
    ],
    "policy_version": "<policy-version>"
  },
  "request_id": "req_01J..."
}
```

Do not include user directories, workspace data, secrets, session identifiers, password state, or mutation capabilities not actually available. `effective_permissions` must come from persisted roles/permissions and role-permission relationships, not a hard-coded `if role == "admin"` branch. If canonical permission tables are missing in the current migration set, add a new forward-only migration for `permissions`, `role_permissions` (and any necessary constraints/indexes); inspect migration history first, and do not edit an applied migration or the reference SQL package.

### Required database-backed test matrix


| Case | Setup/request | Expected result | Failure condition |
| --- | --- | --- | --- |
| Admin success | Real persisted admin user + active database-backed session + explicit `platform.admin` grant; GET endpoint. | 200; only caller’s effective permission/capability summary; request ID; no secret fields. | Any role-name-only bypass or response containing unrelated user/workspace data. |
| Authenticated denied user | Real active session; lacks `platform.admin`; GET endpoint. | 403 `permission_denied`; no capabilities or policy details leaked. | 200, 404 workaround, or permission derived from caller-supplied JSON. |
| Anonymous | No cookie/token. | 401 `unauthorized`. | Any response with admin capabilities. |
| Expired/revoked session | Session persisted then expired/revoked; GET endpoint. | 401; server-side revocation and expiry checked for each request. | A previously valid cookie remains trusted after revocation. |
| Database/RBAC failure | Inject session or permission query failure. | 503 `authorization_unavailable`; fail closed; structured redacted log. | Fallback-to-admin, unprotected 200, or leak of SQL/stack trace. |
| Cross-role spoofing | Non-admin attempts to provide a fake role/user/workspace claim. | 403; server trusts authenticated principal and persisted policy only. | Any client field changes authorization. |
| Permission revoked after session | Create session, remove permission mapping, repeat request. | Denied on next authorization check within defined cache policy (default no positive cache in Sprint 1). | Stale grant remains valid without documented bounded cache invalidation. |
| CSRF/cookie posture | Browser-origin mutating request without required CSRF protection (where cookie auth used). | Rejected according to selected CSRF policy. | Cookie-authenticated mutation succeeds with missing/invalid CSRF proof. |

Never mark FIN-15 complete from the capability endpoint alone: it is a minimal authorization proof route. The role/permission matrix, access checks for all implemented protected APIs, test evidence, route ownership checks and outstanding source acceptance criteria still have to pass.

### FastAPI implementation pattern


The example below is a design sketch, not a drop-in replacement for the current auth/session modules. It must use the repository’s real principal, database session dependency, role/permission tables and error conventions. The dependency should be shared and applied to route groups; domain services must still check resource ownership/workspace grants.

```python
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError

admin_router = APIRouter(prefix="/admin", tags=["Identity & access"])

def require_permission(permission_code: str):
    async def dependency(
        principal = Depends(require_authenticated_user),
        db = Depends(get_db_session),
    ):
        try:
            allowed = await permissions_repository.has_permission(
                db, user_id=principal.user_id, permission_code=permission_code
            )
        except SQLAlchemyError:
            # Log exception with request_id; never log credentials or raw prompt/document text.
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "authorization_unavailable"},
            )
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "permission_denied"},
            )
        return principal
    return dependency

@admin_router.get("/authorization/capabilities", response_model=CapabilitiesResponse)
async def get_authorization_capabilities(
    principal = Depends(require_permission("platform.admin")),
    db = Depends(get_db_session),
):
    return await authorization_service.capabilities_for_subject(db, principal.user_id)
```

Implement `require_authenticated_user`, `get_db_session`, repository and response types using existing project conventions; do not create duplicated independent session verification. Translate exceptions centrally into the standard safe error envelope. Catch only known database/dependency failures, and do not swallow programming errors as ordinary 403 responses. In FastAPI, register static paths such as `/instruments/compare` before parameterized routes such as `/instruments/{instrument_id}` to prevent route-shadowing.

## 5. Full endpoint catalog


The catalog below contains 168 target routes. Full machine-readable inventory is also provided in `FinSight_AI_API_Endpoint_Catalog.csv`, and the matching OpenAPI document is `FinSight_AI_OpenAPI_3.1.yaml`. HTTP route names are proposed canonical targets unless explicitly marked as existing behavior evidence.

### Platform


| Verb | Target path | Purpose | Permission | Execution / retry | Status |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/health/live` | Liveness probe | Public / rate-limited | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/health/ready` | Readiness probe | Public / rate-limited | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/meta/version` | Application build and API version | Public / rate-limited | — | PROPOSED TARGET CONTRACT |

### Identity & access


| Verb | Target path | Purpose | Permission | Execution / retry | Status |
| --- | --- | --- | --- | --- | --- |
| POST | `/api/v1/auth/login` | Create an authenticated session | Public / rate-limited | — | EXISTING BEHAVIOR EVIDENCED; PATH TO VERIFY |
| GET | `/api/v1/auth/me` | Get the current user and effective access summary | Authenticated + resource ACL | — | EXISTING BEHAVIOR EVIDENCED; PATH TO VERIFY |
| POST | `/api/v1/auth/logout` | Invalidate the current session | Authenticated + resource ACL | — | EXISTING BEHAVIOR EVIDENCED; PATH TO VERIFY |
| POST | `/api/v1/auth/recovery-requests` | Request password recovery | Public / rate-limited | Idempotency-Key | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/auth/password-resets` | Complete password recovery | Public / rate-limited | Idempotency-Key | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/auth/sessions` | List the caller’s active sessions | Authenticated + resource ACL | — | PROPOSED TARGET CONTRACT |
| DELETE | `/api/v1/auth/sessions/{session_id}` | Terminate one owned session | Authenticated + resource ACL | Idempotent | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/auth/mfa/challenges` | Begin an MFA challenge | Authenticated + resource ACL | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/auth/mfa/verify` | Verify an MFA challenge | Authenticated + resource ACL | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/users/me` | Read current user profile | Authenticated + resource ACL | — | PROPOSED TARGET CONTRACT |
| PATCH | `/api/v1/users/me` | Update current user profile/preferences | Authenticated + resource ACL | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/admin/authorization/capabilities` | Inspect authorized platform capabilities | platform.admin | — | IMPLEMENTED — FIN-15 PARTIAL |
| GET | `/api/v1/admin/roles` | List platform roles | platform.roles.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/admin/role-permissions` | Assign permissions to a role | platform.roles.manage | Idempotency-Key | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/admin/invitations` | Create an administrator-controlled invitation | platform.users.invite | Idempotency-Key | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/admin/audit-events` | Search security/audit events | platform.audit.read | — | PROPOSED TARGET CONTRACT |

### Workspace & saved research


| Verb | Target path | Purpose | Permission | Execution / retry | Status |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/workspaces` | List caller workspaces | Authenticated + resource ACL | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/workspaces` | Create a workspace | workspace.create | Idempotency-Key | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/workspaces/{workspace_id}` | Read workspace metadata | workspace.read | — | PROPOSED TARGET CONTRACT |
| PATCH | `/api/v1/workspaces/{workspace_id}` | Update workspace metadata | workspace.manage | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/workspaces/{workspace_id}/members` | List workspace members | workspace.members.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/workspaces/{workspace_id}/members` | Add/invite a workspace member | workspace.members.manage | Idempotency-Key | PROPOSED TARGET CONTRACT |
| PATCH | `/api/v1/workspaces/{workspace_id}/members/{user_id}` | Change a member’s workspace role | workspace.members.manage | — | PROPOSED TARGET CONTRACT |
| DELETE | `/api/v1/workspaces/{workspace_id}/members/{user_id}` | Remove a workspace member | workspace.members.manage | Idempotent | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/saved-research` | List saved research artifacts | saved-research.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/saved-research` | Save a research artifact | saved-research.write | Idempotency-Key | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/saved-research/{artifact_id}` | Get a saved artifact | saved-research.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/saved-research/{artifact_id}/duplicate` | Duplicate a saved artifact | saved-research.write | Idempotency-Key | PROPOSED TARGET CONTRACT |
| DELETE | `/api/v1/saved-research/{artifact_id}` | Delete a saved artifact | saved-research.delete | Idempotent | PROPOSED TARGET CONTRACT |

### Jobs & observability


| Verb | Target path | Purpose | Permission | Execution / retry | Status |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/jobs` | List caller-visible jobs | jobs.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/jobs/{job_id}` | Get job status and safe diagnostic summary | jobs.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/jobs/{job_id}/retry` | Retry an eligible failed job | jobs.retry | Idempotency-Key | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/jobs/{job_id}/cancel` | Request job cancellation | jobs.cancel | Idempotency-Key | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/execution-runs/{run_id}` | Inspect an execution run | runs.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/execution-runs/{run_id}/events` | List run events | runs.read | — | PROPOSED TARGET CONTRACT |

### Dashboard & market data


| Verb | Target path | Purpose | Permission | Execution / retry | Status |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/dashboard/summary` | Get dashboard summary and freshness | dashboard.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/dashboard/widgets` | List saved dashboard widgets | dashboard.read | — | PROPOSED TARGET CONTRACT |
| PUT | `/api/v1/dashboard/layout` | Save dashboard layout | dashboard.write | Idempotency-Key | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/watchlists` | List watchlists | watchlists.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/watchlists` | Create watchlist | watchlists.write | Idempotency-Key | PROPOSED TARGET CONTRACT |
| PATCH | `/api/v1/watchlists/{watchlist_id}` | Update watchlist metadata/order | watchlists.write | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/watchlists/{watchlist_id}/items` | Add instrument to watchlist | watchlists.write | Idempotency-Key | PROPOSED TARGET CONTRACT |
| DELETE | `/api/v1/watchlists/{watchlist_id}/items/{instrument_id}` | Remove instrument from watchlist | watchlists.write | Idempotent | PROPOSED TARGET CONTRACT |

### Market data


| Verb | Target path | Purpose | Permission | Execution / retry | Status |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/instruments` | Search instruments | market.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/instruments/{instrument_id}` | Get instrument profile | market.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/instruments/{instrument_id}/bars` | Get historical price bars | market.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/instruments/{instrument_id}/fundamentals` | Get point-in-time fundamentals | market.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/instruments/{instrument_id}/corporate-actions` | Get corporate actions | market.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/instruments/compare` | Compare instruments over a common window | market.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/market/overview` | Get market overview / supported movers | market.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/market/news` | Search licensed/configured news and events | market.news.read | — | PROPOSED TARGET CONTRACT |

### Market ingestion & quality


| Verb | Target path | Purpose | Permission | Execution / retry | Status |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/market-data/providers` | List configured provider capabilities | providers.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/market-data/source-registry` | List approved data sources | sources.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/market-data/ingestion-runs` | Start a market-data ingestion run | market-data.ingest | 202 async | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/market-data/ingestion-runs` | List ingestion runs | ingestion.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/market-data/ingestion-runs/{run_id}` | Get ingestion run details | ingestion.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/market-data/ingestion-runs/{run_id}/reconcile` | Reconcile raw ingestion records | market-data.reconcile | 202 async | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/data-snapshots` | List data snapshots | snapshots.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/data-snapshots/{snapshot_id}` | Get snapshot provenance and quality summary | snapshots.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/data-quality/rules` | List data quality rules | quality.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/data-quality/issues` | Query data quality issues | quality.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/data-quality/issues/{issue_id}/resolve` | Resolve a quality issue | quality.resolve | Idempotency-Key | PROPOSED TARGET CONTRACT |

### Data explorer


| Verb | Target path | Purpose | Permission | Execution / retry | Status |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/data-sources` | List structured data sources | data-sources.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/data-sources` | Register a structured source | data-sources.manage | Idempotency-Key | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/data-sources/{source_id}/test` | Test source connectivity safely | data-sources.manage | Idempotency-Key | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/data-sources/{source_id}/schema` | Discover allowlisted source schema | data-sources.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/data-queries/validate` | Validate a read-only query or query plan | data-queries.run | Idempotency-Key | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/data-queries` | Execute a bounded read-only data query | data-queries.run | 202 async | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/data-queries/{query_id}` | Get saved query definition | data-queries.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/datasets/imports` | Import a dataset for preview and validation | datasets.import | 202 async | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/datasets/{dataset_id}/transformations` | Apply a versioned dataset transformation | datasets.transform | 202 async | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/datasets/{dataset_id}/lineage` | Get dataset lineage | datasets.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/datasets/{dataset_id}/exports` | Export an authorized dataset | datasets.export | 202 async | PROPOSED TARGET CONTRACT |

### Research & RAG


| Verb | Target path | Purpose | Permission | Execution / retry | Status |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/research/sources` | List research source connectors | research.sources.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/research/sources` | Register a source or research feed | research.sources.manage | Idempotency-Key | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/documents` | Search/list research documents | documents.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/documents` | Upload/register a document for ingestion | documents.create | 202 async | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/documents/{document_id}` | Get document metadata/status | documents.read | — | PROPOSED TARGET CONTRACT |
| PATCH | `/api/v1/documents/{document_id}` | Update document metadata | documents.manage | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/documents/{document_id}/versions` | List document versions | documents.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/documents/{document_id}/chunks` | Preview extracted chunks | documents.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/documents/{document_id}/reindex` | Re-process/re-index a document version | documents.reindex | 202 async | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/documents/{document_id}/retry-processing` | Retry a recoverable processing failure | documents.reprocess | 202 async | PROPOSED TARGET CONTRACT |
| DELETE | `/api/v1/documents/{document_id}` | Delete/archive a document under lifecycle policy | documents.delete | Idempotent | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/documents/search` | Search documents/chunks with access filters | documents.search | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/knowledge-indexes` | List knowledge indexes | knowledge-indexes.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/knowledge-indexes/{index_id}/reconcile` | Reconcile index/chunk/vector consistency | knowledge-indexes.manage | 202 async | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/retrieval-runs` | Run authorized retrieval and capture trace | retrieval.run | 202 async | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/retrieval-runs/{retrieval_run_id}` | Get retrieval trace and authorized citations | retrieval.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/documents/{document_id}/access-grants` | List document access grants | documents.acl.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/documents/{document_id}/access-grants` | Grant document access | documents.acl.manage | Idempotency-Key | PROPOSED TARGET CONTRACT |
| DELETE | `/api/v1/documents/{document_id}/access-grants/{grant_id}` | Revoke document access | documents.acl.manage | Idempotent | PROPOSED TARGET CONTRACT |

### AI Financial Analyst


| Verb | Target path | Purpose | Permission | Execution / retry | Status |
| --- | --- | --- | --- | --- | --- |
| POST | `/api/v1/conversations` | Create conversation | conversations.create | Idempotency-Key | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/conversations` | List caller conversations | conversations.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/conversations/{conversation_id}` | Get conversation and message history | conversations.read | — | PROPOSED TARGET CONTRACT |
| DELETE | `/api/v1/conversations/{conversation_id}` | Delete/archive conversation | conversations.delete | Idempotent | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/conversations/{conversation_id}/messages` | Submit an analyst message | conversations.write | 202 async | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/conversations/{conversation_id}/messages/{message_id}/regenerate` | Regenerate an answer | conversations.write | 202 async | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/conversations/{conversation_id}/generation/stop` | Request generation stop | conversations.write | Idempotency-Key | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/analysis/financial-questions` | Answer a financial question with source-backed tools | analysis.run | 202 async | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/analysis/tools` | List caller-available financial tools | analysis.tools.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/analysis/tools/{tool_code}/execute` | Execute one allowlisted analytical tool | analysis.tools.execute | 202 async | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/analysis/feedback` | Record feedback on an AI answer | analysis.feedback | Idempotency-Key | PROPOSED TARGET CONTRACT |

### Settings & integrations


| Verb | Target path | Purpose | Permission | Execution / retry | Status |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/settings/models` | List model/inference configuration | settings.models.read | — | PROPOSED TARGET CONTRACT |
| PATCH | `/api/v1/settings/models` | Update model settings draft | settings.models.manage | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/settings/models/test` | Test model connectivity/configuration | settings.models.manage | Idempotency-Key | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/settings/models/activate` | Activate a validated model configuration | settings.models.activate | Idempotency-Key | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/settings/embeddings` | Get embedding/chunk/retrieval configuration | settings.rag.read | — | PROPOSED TARGET CONTRACT |
| PATCH | `/api/v1/settings/embeddings` | Update RAG configuration draft | settings.rag.manage | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/settings/embeddings/test` | Test embedding configuration | settings.rag.manage | Idempotency-Key | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/settings/providers` | List provider settings safely | settings.providers.read | — | PROPOSED TARGET CONTRACT |
| PATCH | `/api/v1/settings/providers/{provider_id}` | Update provider configuration draft | settings.providers.manage | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/settings/providers/{provider_id}/test` | Test provider credentials and coverage | settings.providers.manage | Idempotency-Key | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/settings/config-versions` | List effective configuration versions | settings.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/settings/config-versions/{version_id}/rollback` | Roll back to a prior safe configuration | settings.manage | Idempotency-Key | PROPOSED TARGET CONTRACT |

### Portfolio & analytics


| Verb | Target path | Purpose | Permission | Execution / retry | Status |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/portfolios` | List portfolios | portfolios.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/portfolios` | Create portfolio | portfolios.write | Idempotency-Key | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/portfolios/{portfolio_id}` | Get portfolio detail | portfolios.read | — | PROPOSED TARGET CONTRACT |
| PATCH | `/api/v1/portfolios/{portfolio_id}` | Update portfolio settings | portfolios.write | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/portfolios/{portfolio_id}/transactions` | Record a portfolio transaction | portfolios.transactions.write | Idempotency-Key | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/portfolios/{portfolio_id}/snapshots` | List portfolio snapshots | portfolios.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/portfolios/{portfolio_id}/snapshots` | Create portfolio snapshot | portfolios.calculate | 202 async | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/portfolios/{portfolio_id}/performance` | Calculate/view portfolio performance | portfolio-analytics.read | 202 async | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/portfolios/{portfolio_id}/allocation` | Analyze asset/sector/geographic allocation | portfolio-analytics.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/portfolios/{portfolio_id}/attribution` | Calculate performance attribution | portfolio-analytics.read | — | PROPOSED TARGET CONTRACT |

### Valuation & risk


| Verb | Target path | Purpose | Permission | Execution / retry | Status |
| --- | --- | --- | --- | --- | --- |
| POST | `/api/v1/valuations/dcf-runs` | Run DCF valuation | valuation.run | 202 async | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/valuations/dcf-runs/{run_id}` | Get DCF run and result | valuation.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/valuations/dcf-runs/{run_id}/sensitivity` | Get valuation sensitivity matrix | valuation.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/risk-runs` | Run quantitative portfolio risk analysis | risk.run | 202 async | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/risk-runs/{run_id}` | Get risk run and metrics | risk.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/risk-runs/{run_id}/time-series` | Get risk metric time series | risk.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/risk-runs/{run_id}/stress-tests` | Evaluate configured/custom stress scenarios | risk.run | 202 async | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/risk-runs/{run_id}/stress-tests` | Get stress-test results | risk.read | — | PROPOSED TARGET CONTRACT |

### Strategy & workflows


| Verb | Target path | Purpose | Permission | Execution / retry | Status |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/screens` | List saved screens | screens.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/screens` | Create saved screen | screens.write | Idempotency-Key | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/screen-runs` | Run an instrument screen | screens.run | 202 async | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/screen-runs/{run_id}` | Get screening results and ranking | screens.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/strategies` | List strategies | strategies.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/strategies` | Create a strategy | strategies.write | Idempotency-Key | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/strategies/{strategy_id}/versions` | Create immutable strategy version | strategies.write | Idempotency-Key | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/strategies/{strategy_id}/readiness-checks` | Check strategy readiness | strategies.run | Idempotency-Key | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/signals/runs` | Generate signals for a strategy version | signals.run | 202 async | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/signals` | List signals and their status | signals.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/workflows` | List workflows | workflows.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/workflows` | Create workflow definition | workflows.write | Idempotency-Key | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/workflows/{workflow_id}/runs` | Run workflow | workflows.run | 202 async | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/workflows/{workflow_id}/schedules` | Create/update workflow schedule | workflows.schedule | Idempotency-Key | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/backtest-runs` | Start historical backtest | backtests.run | 202 async | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/backtest-runs/{run_id}` | Get backtest status and summary | backtests.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/backtest-runs/{run_id}/trades` | Get simulated backtest trades | backtests.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/backtest-runs/{run_id}/equity-curve` | Get backtest equity curve and drawdown | backtests.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/backtest-runs/compare` | Compare authorized backtest runs | backtests.read | Idempotency-Key | PROPOSED TARGET CONTRACT |

### Reporting


| Verb | Target path | Purpose | Permission | Execution / retry | Status |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/v1/reports` | List reports | reports.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/reports` | Create report specification | reports.write | Idempotency-Key | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/reports/{report_id}` | Get report metadata/content status | reports.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/reports/{report_id}/exports` | Generate PDF/CSV export | reports.export | 202 async | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/reports/{report_id}/exports/{export_id}` | Check report export status | reports.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/reports/{report_id}/access-grants` | Share report with user/workspace | reports.share | Idempotency-Key | PROPOSED TARGET CONTRACT |
| DELETE | `/api/v1/reports/{report_id}/access-grants/{grant_id}` | Revoke report access | reports.share | Idempotent | PROPOSED TARGET CONTRACT |

### Privacy & account lifecycle


| Verb | Target path | Purpose | Permission | Execution / retry | Status |
| --- | --- | --- | --- | --- | --- |
| POST | `/api/v1/privacy/data-exports` | Request personal data export | privacy.export | 202 async | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/privacy/deletion-requests` | Request account/data deletion | privacy.delete | 202 async | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/privacy/requests/{request_id}` | Check privacy request status | privacy.read | — | PROPOSED TARGET CONTRACT |
| GET | `/api/v1/api-credentials` | List caller API credentials metadata | privacy.credentials.read | — | PROPOSED TARGET CONTRACT |
| POST | `/api/v1/api-credentials` | Create API credential | privacy.credentials.manage | Idempotency-Key | PROPOSED TARGET CONTRACT |
| DELETE | `/api/v1/api-credentials/{credential_id}` | Revoke API credential | privacy.credentials.manage | Idempotent | PROPOSED TARGET CONTRACT |

## 6. Domain contracts and persistence alignment


The canonical schema/ERD reference and component diagrams are target-state references. Implement only the tables needed for the approved current story slice, and use canonical names where a matching table exists. Do not invent an alternate schema simply because a diagram uses shorthand. Verify actual schema/migrations in the repository before writing ORM classes.

| API domain | Canonical entity families identified in supplied design | Persistence/logic rules |
| --- | --- | --- |
| Identity/access | users, roles, permissions, role_permissions, auth_sessions, password_reset_tokens, mfa_factors, workspaces, workspace_members, workspace_invitations | Session state and RBAC must be persisted. Use unique constraints/foreign keys/indexes. Secret values are not returned by APIs. |
| Provider and market data | market_data_providers/provider_connections/provider_coverage/refresh_policies, ingestion_batches/raw_data_records/data_snapshots/data_quality_rules/data_quality_issues, instruments/companies, price_bars/fundamentals/corporate_actions | Track provider/request/hash/batch, validation decisions, accepted/rejected outcomes, quality lineage and snapshot references. Keep end-of-day vs realtime labels honest. |
| Documents/RAG | research_sources/source_registry, research_documents, document_versions, document_chunks, chunk_embeddings, knowledge_indexes, retrieval_runs, retrieval_run_chunks, document_access_grants | Document → version → extracted chunks → embedding/index version → permission-filtered retrieval trace → citation. Handle stale/orphaned vectors on delete/re-index with reconciliation. |
| Conversation and AI | conversations/messages/tool definitions/config versions plus retrieval-run/citation entities where represented in canonical SQL | Model outputs are not a source of numeric truth. Persist model/config version, approved tools, snapshot IDs, citations, run/status and safe diagnostics. |
| Portfolio/valuation/risk | portfolios, portfolio_transactions, portfolio_snapshots, portfolio_positions, portfolio_returns/portfolio_cash_balances, valuation model/run/assumption/forecast/sensitivity entities, risk runs/metric/time-series/covariance/stress entities | Deterministic calculation engine; every output pins as-of and input snapshot/model/config. Decimal-safe money/units, currency, method and completeness warnings. |
| Screens/workflows/backtests | saved_screens/screen_runs/screen_results, strategies/strategy_versions/strategy_variants, signals/signal_observations/signal_status_history, workflows/runs/schedules, backtest_runs/backtest_trades/backtest_equity_points | Immutable versioned definitions; no out-of-band tool calls; record data snapshots, costs/slippage/benchmark, seed and execution events. Historical simulation only. |
| Jobs/reporting | background_jobs, job_attempts, execution_runs, execution_steps, execution_events, service_health_checks, reports, report_data_snapshots, report_citations, report_access_grants | Durable job/run state and provenance in PostgreSQL. File bytes in object storage with controlled retention, URI and MIME metadata. |

## 7. Asynchronous operations, jobs and reliability


Any lengthy provider refresh, document parsing/OCR, chunking/embedding/indexing, large query/export, LLM orchestration where latency warrants it, valuation/risk Monte Carlo, workflow and backtest/report generation should return `202 Accepted` with `job_id`, optional `run_id`, initial status and request ID. A small fast operation may be synchronous only if it still meets latency targets and has bounded work.

```json
{
  "job_id": "<uuid>",
  "run_id": "<uuid-or-null>",
  "status": "queued",
  "request_id": "req_01J...",
  "status_url": "/api/v1/jobs/<uuid>"
}
```

Allowed job states: `queued → running → completed | failed | cancelled`; cancellation and retry follow explicit state transitions. Store attempts and failure codes/messages safe for users; internal diagnostics stay redacted and access-restricted. Retry transient errors with bounded exponential backoff and jitter. Do not retry validation, permission or irrecoverable source/licensing failures blindly. `GET /jobs/{id}` must verify the caller can access the underlying domain object, not only the job row.

## 8. Market data and data quality contract


Release 1 baseline is historical daily US-equity data. A response must say what was queried and what it means, including provider/source, symbol/instrument identity, interval, currency, requested and actual date window, `as_of`, snapshot ID, freshness state (`fresh`, `cached`, `stale`, `unknown` or agreed enum), data mode (`historical`, `end_of_day`, `delayed`, `demo` where relevant), adjusted/unadjusted state, missing coverage and quality warnings. Do not infer intraday/realtime capability from a generic provider type.

Ingestion is an auditable pipeline: provider adapter → raw payload/hash → normalization and instrument mapping → schema/quality validation → accept/reject/quarantine outcomes → snapshot → accepted rows → lineage metadata. Re-running the same batch must not duplicate data or create duplicate effects. Reconciliation should report drift rather than silently overwrite provenance. Provider licences and entitlements gate display and export.

## 9. Research, RAG, documents and AI safety


Document lifecycle: validate upload/source and access → parse/extract/OCR (optional for scans) → enrich metadata and version → section/page/table-aware chunking → embedding generation → index → searchable status. Re-indexing pins parser/chunking/embedding/model/index versions. Deletion and version supersession must remove/reconcile stale vectors and objects under retention rules. Chunk metadata should preserve document ID, version ID, page/section/table labels and offsets where supported.

RAG execution order is mandatory: authenticate → authorize workspace/document grants → embed query → filter eligible indexes/chunks → retrieve/rank → persist retrieval trace → construct bounded context from authorized chunks → call configured model → validate response/citations → return UI answer. Untrusted document text is never an instruction to override policy. Tools are allowlisted, typed and independently authorized. Every citation maps to canonical document/version/chunk or structured data/snapshot; never invent URLs, page numbers or evidence.

Retrieval outputs should contain `retrieval_run_id`, ranking/similarity fields where permitted, source IDs, title, source URI or controlled internal URI, filing/publication date, page/section, excerpt only if the caller can still access it, and a stable citation ID. Enforce max context tokens/chunks, timeout, query limits, prompt-injection checks and log redaction.

## 10. Financial calculation contract


DCF, portfolio performance, attribution, VaR/CVaR, drawdown, Monte Carlo, stress tests, screening signals and backtests run through deterministic services with typed/versioned inputs. Every run stores: actor/workspace, input entity IDs, `data_snapshot_id`, algorithm/model/config version, dates/lookback/frequency, assumptions, currency, parameters, status, reproducibility seed (where applicable), warnings/limitations and result IDs. A report or AI answer must distinguish calculations from explanatory natural-language text.

Use decimal-safe storage for currency and trading-like quantities even though no broker orders are available in Release 1. Explicitly define return method, annualization, benchmark alignment, missing values, survivorship/look-ahead controls and cost/slippage assumptions for backtests. Refuse or mark output incomplete when mandatory inputs are missing; never silently replace missing history with present-day values.

## 11. Reporting, privacy and artifact access


A report stores report metadata, input snapshot usage (`report_data_snapshots`), source citations (`report_citations`), access grants and export/job state. Generated files are stored in controlled object/file storage; the database records the artifact URI, MIME type, timestamps and retention metadata. Recheck owner/workspace/report permissions both before generating and before serving/download. Signed file links are short-lived and never a substitute for authorization.

Privacy export/deletion and API credential routes must be implemented only with explicit SRS acceptance, retention/legal-hold policy and test coverage. Return credential secrets once at creation only; store a hash, show metadata thereafter and support immediate revocation. Account deletion is an auditable workflow that respects retention/backup and dependency relationships.

## 12. Non-functional requirements and security gates


| Control | API requirement / implementation acceptance gate |
| --- | --- |
| Authorization | Default-deny, explicit permission strings, resource owner/workspace ACL on reads and mutations, no insecure direct object references; anonymous/other-tenant tests. |
| Session security | Expiry/revocation checked server-side; generic login errors; rate limit/lockout policy; optional MFA only when truly enabled; secure cookie/CSRF policy. |
| Secrets and privacy | Secret manager references only; secret output/log scan; prompt/document excerpts minimized; no sensitive query text in routine logs. |
| Input safety | Pydantic constraints, allowlisted sort/filter/query/tool fields, parameterized SQL, bounded upload types/sizes, parser isolation and output encoding. |
| RAG safety | Access filter before prompt assembly; prompt-injection tests; citation resolvability; context caps; revoked grants honored. |
| Reliability | Idempotency + DB uniqueness, bounded retries, durable job states, cancellation semantics, reconciliation of partial writes/artifacts. |
| Observability | Structured logs with request/correlation IDs, actor/resource/action/status/duration; safe error codes; health/readiness; no secrets. |
| Performance | SRS NFR remains authoritative. Define targets during requirement review; use pagination, DB indexes, bounded queries and performance tests; do not invent pass thresholds in API docs. |
| Data rights | Store source attribution/terms and coverage; gate display/export according to provider entitlements; label stale/demo/historical data. |
| Testing and release | TDD; unit/API/DB/integration/security/negative/E2E tests; migration rollback plan; CI security/dependency checks; source RTM and evidence updated. Critical auth/data-integrity/secret/injection defects block release. |

## 13. Error and failure behavior


| Scenario | Contract |
| --- | --- |
| Authentication absent/invalid | 401 `unauthorized`; do not leak whether user exists. |
| Permission denied | 403 `permission_denied`; message safe and generic. |
| Object missing or inaccessible | Use selected 404/403 policy consistently; no cross-workspace existence leak. |
| Authorization DB unavailable | 503 `authorization_unavailable`; fail closed; never assume platform/admin privileges. |
| Provider/model unavailable | 503 or domain-safe failed job; no silent fabricated data. Return run/job IDs if work was accepted. |
| Validation issue | 422 with field-level safe errors; no stack trace. |
| Duplicate request | Return original idempotent result when request hash matches; otherwise 409. |
| Partial indexing/deletion | Expose nonterminal/failed state, enqueue safe reconciliation, preserve audit and lineage. |
| Stale/missing market data | Return available data with freshness/quality disclosure only when contract permits; otherwise safe unavailable/incomplete outcome. |

## 14. Sprint 1 implementation sequence — avoid mixing work


| Step | Concrete deliverable | Acceptance evidence |
| --- | --- | --- |
| 1. Baseline audit | Inspect actual route declarations, app router mounting/prefixes, auth dependency/session model, migrations applied, tests, cookie/CSRF policy and CI. Record existing URLs before refactor. | Before/after route inventory; migration inventory; run current tests; no scope inference. |
| 2. RBAC model/migration | Verify schema for permission records and role_permissions. Add only a forward migration if missing; seed stable permission codes with explicit mappings in test fixtures and controlled bootstrap process. | Migration up/down strategy; FK/unique/index checks; test DB setup; no edit to existing applied migrations. |
| 3. Authorization dependency | Implement `require_permission(permission_code)` over actual authenticated principal + DB-backed session and role/permission joins. Fail closed on any dependency/DB error. | Unit tests for allow/deny + integration tests with real database-backed sessions. |
| 4. Decision A endpoint | Add `GET /api/v1/admin/authorization/capabilities` via actual router and dependency; return small DTO only. | Admin 200, non-admin 403, anonymous/expired/revoked 401, DB/RBAC unavailable 503; permission revocation and no secret leakage. |
| 5. Regression + security | Verify current `/auth/login`, `/auth/me`, `/auth/logout` behavior and frontend integration; cookie/CSRF tests as applicable; lint/type/test/secret scanning. | Run actual test commands and record outcomes; don’t alter planned test register statuses without evidence. |
| 6. Documentation/traceability | Generate OpenAPI from FastAPI at runtime; compare against this target spec; record implemented-vs-proposed; update the requirement/story links and append-only execution record. | `/openapi.json` route diff, test evidence, changed files, migration ID and unresolved gaps. |

## 15. Endpoint ownership, permissions and traceability rules


The `FinSight_AI_API_Endpoint_Catalog.csv` includes every target endpoint, status, permission and derived story/requirement mapping. The `FinSight_AI_API_Story_Coverage.csv` preserves all 72 source aliases, Jira keys, acceptance summaries, test execution, implementation status and outstanding gaps from the source matrix. `FinSight_AI_API_Requirement_Traceability.csv` preserves each of the source RTM’s requirement/data-integrity rows and original evidence/status/test fields, adding only a proposed API family and explicit contract note.

Route-to-story mapping is a design aid and is not a substitute for acceptance-criterion traceability. For each Jira story, engineers must connect every acceptance criterion to one or more endpoints/services/schema changes/tests and show test evidence. Requirements without mapped source stories remain gaps; do not infer scope or change Jira/SRS baselines from this document.

## 16. Decisions required before broad implementation


| Decision | Current contract stance / required owner action |
| --- | --- |
| Existing auth path compatibility | Inspect live code and frontend. Choose compatibility aliases or a planned migration to `/api/v1`; don’t assume the target paths already exist. |
| Session identifier and cookie | Keep current working mechanism; document actual cookie name/token type and rotation/expiry/revocation before releasing the API contract. |
| RBAC bootstrap and platform.admin grants | Approve a least-privilege bootstrap mechanism; no default public admin, no implicit promotion by display name. |
| Unmapped SRS requirements | RTM records 81 requirements without explicit story mapping. Product owner must categorize MVP vs deferred vs missing story; no silent omissions. |
| Release scope and story labels | Preserve source release labels; FS-07-04 and FS-08-04 Release 2 only. Four-sprint assignment does not override the gate. |
| Data provider selection/license | Select source/coverage/allowed display/export and secret manager policy before exposing provider write APIs. |
| Deployment and performance targets | Select deployment target/owner, HTTPS/cookie verification, production migration owner, objective NFR thresholds and monitoring ownership. |

## 17. Definition of Done for each API story


A story is not done until all of its source acceptance criteria are met; its schema/service/API changes are reviewed; positive and negative auth/object-scope tests pass; input validation and error handling are stable; idempotency/concurrency is tested where applicable; observability is redacted; OpenAPI and examples reflect runtime; the source RTM records actual evidence and independent test execution; and release/trading boundaries have been checked. Do not mark blocked or not-yet-built tests as PASS. Current Sprint 1 plan defaults tests to NOT RUN unless execution evidence says otherwise.

## 18. Source artifacts used


This contract was grounded in the uploaded SRS (49 pages), Database Schema & ERD Reference (81 pages), Technical Design & Implementation Plan (30 pages), Component Diagram Companion (19 pages), enhanced Jira backlog (72 story entries), full four-sprint allocation, Sprint 1 Test Plan and its Management Register, `traceability-matrix(1).md`, and `srs-addendum(1).md`. The architecture diagrams shared in the conversation were used to align the market-data, document/RAG, overall system, portfolio, risk, reporting and Release 2 trading domains.

**Authority reminder:** the original SRS remains authoritative. The addendum is supplemental/draft; supplied schema/ERD and architecture are target-state design, not proof of live deployment. This contract proposes design details but does not change source files, Jira scope, source release labels, implementation status or test execution status.
