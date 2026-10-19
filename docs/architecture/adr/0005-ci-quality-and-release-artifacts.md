# ADR-0005: CI quality gates and versioned release artifacts

- **Status:** Accepted; workflow configured, remote execution pending
- **Context:** Reproducible builds and visible quality/security checks are required, while no deployment target is configured.
- **Decision:** Extend one GitHub Actions workflow to validate locked frontend/backend dependencies, tests, builds, hygiene and dependency security before packaging a versioned artifact with commit metadata/checksum where available.
- **Alternatives considered:** Duplicate CI workflows, unpinned dependency installation, or automatic deployment to an unselected provider. These reduce reproducibility or introduce unapproved operational choices.
- **Consequences:** Packaging depends on the configured CI jobs, but actual GitHub runner success and branch-protection enforcement require a remote run/settings. Artifacts can be promoted by version/SHA; deployment and rollback remain operator-controlled per the release runbook.

