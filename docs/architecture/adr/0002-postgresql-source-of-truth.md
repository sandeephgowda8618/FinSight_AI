# ADR-0002: PostgreSQL as structured source of truth

- **Status:** Accepted; current implementation and project baseline
- **Context:** Current login, user and session operations persist to PostgreSQL. The schema reference defines a broader relational target model.
- **Decision:** Use PostgreSQL as authoritative storage for implemented structured identity/session records. Keep the current implementation limited to its `roles`, `users`, and `auth_sessions` migration subset.
- **Alternatives considered:** In-memory/session-cookie-only persistence or a document database. These do not match the persistence baseline and would not provide current cross-request revocation.
- **Consequences:** API availability depends on PostgreSQL for authenticated operations; tests use disposable PostgreSQL. pgvector and the broader target entities are not implemented by this decision's current scope.

