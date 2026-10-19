# ADR-0004: Versioned migrations and environment configuration

- **Status:** Accepted; partially implemented
- **Context:** The supplied schema is a target reference, not an instruction to deploy every table. Runtime environments need different database and origin settings.
- **Decision:** Keep reference schema files immutable; implement schema changes as versioned migration files and load environment-specific values outside application source. Use safe placeholder templates only.
- **Alternatives considered:** Applying the full target SQL directly or embedding credentials/configuration in code. Both increase data and secret risk.
- **Consequences:** The current identity migration is a one-time SQL script for a new development/test database. A general migration runner, production ownership, and deployed environment are not yet established; production migration strategy needs an owner and forward/rollback plan.

