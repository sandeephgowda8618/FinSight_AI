# ADR-0003: Opaque server-validated browser sessions

- **Status:** Accepted; implemented for the current authentication slice
- **Context:** The browser needs a session that can be revoked and checked against user status and expiry. The identity schema includes `auth_sessions` and a refresh-token hash field.
- **Decision:** Hash passwords with Argon2 through the established library. Issue a random opaque cookie token, store only its SHA-256 digest, and validate active, unexpired session/user state in PostgreSQL on protected requests. Set an HttpOnly, SameSite=Lax cookie and use Secure in production.
- **Alternatives considered:** Plaintext passwords, client-side authorization state, or a self-contained token without server-side revocation. These fail the current security/persistence requirements.
- **Consequences:** Session lookup requires the database and logout can revoke the session. Cookie origin/configuration and session TTL must remain aligned between deployment and API. Password recovery, MFA, invitation workflow, and broader role administration are not implemented.

