# ADR-0001: Modular Next.js and FastAPI application

- **Status:** Accepted; current implementation
- **Context:** The project baseline requires a Next.js/React frontend and modular FastAPI backend. Current code has one Next.js app and one FastAPI process; the full target domain modules are not present.
- **Decision:** Keep presentation in Next.js and API/authentication/persistence boundaries in FastAPI. Begin as a modular monolith; do not split services without a demonstrated requirement.
- **Alternatives considered:** A single full-stack server; separate microservices. Neither is established by the approved baseline/current implementation.
- **Consequences:** The browser owns presentation state only; backend routes own validation and authorization. Domain modules/adapters/workers remain future target boundaries, not claims about current code.

