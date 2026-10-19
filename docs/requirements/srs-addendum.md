# SRS addendum and change-control record

- Document: FinSight AI SRS Addendum
- Version: 0.1 (supplemental baseline, 2026-10-19)
- Status: Draft for traceability and decision capture
- Relationship: Supplements but does not replace or amend the original SRS. The SRS remains authoritative until its owner approves a revision. Source PDFs, SQL, diagrams, and original plans remain read-only.
- Related artifacts: traceability-matrix.md, traceability-requirements.csv, traceability-stories.csv, docs/architecture/README.md, IMPLEMENTATION_STATUS.txt, conversation.txt.

## Traceability conventions

Each source SRS FR/NFR ID and DIR rule is listed individually with PDF page/domain, mapped source story aliases and verified Jira keys where present, story acceptance criteria, supplied test IDs, independent test-execution status, implementation evidence, and gaps. A blank link is recorded as a gap, not guessed.

Implementation status and test status are distinct. Implementation uses IMPLEMENTED — VERIFIED, PARTIAL, PLANNED, NOT IMPLEMENTED, BLOCKED, or NOT ASSESSED. Test execution uses PASS, FAIL, BLOCKED, or NOT RUN. Passing tests establish only the behaviors actually exercised. Missing implementation is not an approved requirement change.

## Confirmed boundaries and release distinctions

Current runtime has a Next.js sign-in page/runtime API-origin endpoint, FastAPI login/current-user/logout, PostgreSQL identity/session persistence through one versioned identity migration, and the CI/test/release-package workflow documented in docs/architecture/README.md. Password recovery, app-admin invitations, MFA, role administration, auth audit subsystem, health endpoint, uploads/RAG, market-data providers, analytics, workers, and broker order execution are absent.

Release 1 remains read-only financial research; optional trading SQL is not applied. The four-sprint plan explicitly keeps FS-07-04 and FS-08-04 Release 2 only. Their labels must remain unchanged; sprint placement does not authorize Release 1 trading work.

## Traceability snapshot and limitations

Read-only extraction found 399 FR/NFR IDs and 10 DIR rules. All 409 are represented. All 72 source aliases were matched to a live Jira key on 2026-10-19. Of 23 Sprint 1 aliases, 22 retain explicit SRS requirement IDs; FS-11-09/FIN-80 is a management/process story with no direct SRS ID and is recorded as such. 328 requirement rows have a story mapping from Jira descriptions or explicit Sprint 1 test-plan traceability; 81 do not. The Sprint 1 management inventory has 54 test cases; the separate execution register has 52 explicit rows. TC_ENV_001 and TC_ENV_002 have no execution row and remain at the source-plan default NOT RUN. 104 requirement rows have a supplied story- or requirement-linked Sprint 1 test; 305 have no linked test in the supplied inventory.

The Jira project query also returned FIN-84 through FIN-87 without a source FS alias. They are not silently mapped. The FS-11-01 estimate mismatch remains: detailed backlog 3 points, four-sprint plan/live Jira 2 points. No Jira or source-file changes were made.

## Open requirement and catalog questions

1. Unmapped SRS scope (Q-009): 81 requirements lack a direct mapping in either Jira issue descriptions or the Sprint 1 test-plan links. The matrix does not infer whether they are omitted stories, non-MVP, or future scope. Product owner must identify MVP/Release 1 requirements, deferred requirements and release labels, and whether new/amended stories and tests are needed. No Jira changes pending approval.
2. Password recovery and onboarding: FR-P1-03 and FR-P1-04 remain required with incomplete implementation. A local operator CLI exists; no app invitation workflow exists. These are not approved scope reductions.
3. Deployment requirements: deployed HTTPS/cookie verification and production migration ownership need a selected deployment target and named owner.
4. Jira catalog mismatch (Q-010): FIN-84–FIN-87 have no source alias. Confirm supplemental issue status or provide approved mappings; do not infer aliases.
5. Planning estimate mismatch: preserve current values until resolved through normal project planning.

## Change-control procedure

1. Record rationale, owner, and proposed decision in conversation.txt; do not overwrite the SRS.
2. Identify affected requirement IDs and assess security, release boundary, and dependencies.
3. Map impacts to stories, Jira keys, acceptance criteria, estimates, release labels, and dependencies. Obtain approval before Jira edits.
4. Review architecture/API contracts and canonical schema. Approved schema work uses new versioned migrations; never edit supplied SQL references or rewrite applied migration history.
5. Add/update tests and IDs. Keep source plans immutable and record actual results only in a separate execution register.
6. Update the RTM, architecture docs, and implementation status; run the validator and relevant checks.
7. Review changes for Release 2 trading gates, secret hygiene, and source immutability.

