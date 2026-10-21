# FinSight AI API Design Pack

This developer-facing API pack combines the target API contract with implementation status. Most operations remain proposed. GET /api/v1/admin/authorization/capabilities is implemented, but FIN-15 remains PARTIAL and its broader acceptance criteria are not all satisfied. Source release labels and implementation/test statuses are preserved.

## Files

- `FinSight_AI_API_Design_and_Implementation_Contract.md` — full specification with conventions, RBAC, decision A, security/test matrix, domain contracts, complete endpoint inventory, implementation sequence and source boundaries.
- `FinSight_AI_API_Design_and_Implementation_Contract.docx` — formatted Word copy of the specification.
- `FinSight_AI_OpenAPI_3.1.yaml` — machine-readable proposed OpenAPI 3.1 contract for the Release 1 target. Request/response examples are explicitly illustrative where the final Pydantic DTO is not yet implemented.
- `FinSight_AI_API_Endpoint_Catalog.csv` — searchable catalog of every proposed operation, permission, story/requirement linkage, async/idempotency and contract status.
- `FinSight_AI_API_Story_Coverage.csv` — all 72 source story aliases with source Jira key, release, acceptance criteria, tests, implementation status and gaps preserved.
- `FinSight_AI_API_Requirement_Traceability.csv` — all 409 requirement/data-integrity rows from the source traceability matrix, retaining source statuses and test execution, with an added proposed API family mapping.

## Critical guardrails

1. The original SRS remains authoritative. Source schema/ERD and diagrams are target-state, not proof all tables or routes exist in the runtime.
2. Decision A is included: add a narrow platform-admin-only capability endpoint using `require_permission("platform.admin")`, tested against real database-backed sessions.
3. Release 1 has no broker/order/paper-trading endpoints. Stories FS-07-04 / FIN-54 and FS-08-04 / FIN-60 remain Release 2 only; do not apply the optional trading SQL.
4. Proposed route names are not claims of implementation. Inspect the actual Sprint 1 FastAPI router and existing login/session paths before compatibility or migration work.
5. Traceability is not scope approval. The source RTM has unmapped requirement rows; the product owner must disposition them rather than silently infer or omit them.
