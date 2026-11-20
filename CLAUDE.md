# Pinotechrd.Security

.NET 10 multi-tenant security library, two NuGet packages: `Pinotechrd.Security` and `Pinotechrd.Security.Abstractions`.
Human docs: CONTRIBUTING.md (branch model, commit style), docs/ARCHITECTURE_DECISIONS.md (decisions not in the code). Read them, do not copy them here.

## Commands
- Narrow gate (Stop hook): `.claude/verify.ps1` — Release build with warnings as errors, then every test outside `Postgres`.
- One area: `.claude/verify.ps1 -Filter "FullyQualifiedName~Pinotechrd.Security.Tests.Core"` (folders: Authorization, Core, Data, Entities, Extensions, Hosting, Interfaces, Postgres, Tenancy).
- Full gate, once per unit and for any tenancy, data or auth change: `.claude/verify.ps1 -Full` (mirrors `.github/workflows/ci.yml`, the source of truth; ~5 min).
- Multi-node validation (two nodes, PgBouncer, a role per tenant, Redis; CI job `multinode`): `tests/MultiNode/run.ps1` (Docker; ~2 min). Run it for changes to sessions, tokens, caching or tenancy.

## Facts not in the code
- The `Postgres` tests need a running Docker daemon (Testcontainers). They fail instead of skipping on purpose, so a missing Docker cannot hide a broken tenant-isolation guarantee. Never make them skip.
- The library ships no EF migrations: applications generate their own per tenant. New tables must be opt-in in the model, or `MigrateAsync` breaks every consumer (EF Core `PendingModelChangesWarning`).
- New public members go in `src/*/PublicAPI.Unshipped.txt` (the build fails otherwise). `PublicAPI.Shipped.txt` changes only during a release.
- Behaviour changes go in `CHANGELOG.md` under the unreleased preview, with **breaking** marked.
- Files use CRLF (`.editorconfig`); a PostToolUse hook runs `dotnet format whitespace` on each edited `.cs` file.

## Rules with exceptions
- Every branch is `<type>/<issue>-<slug>` for an open GitHub issue. A PreToolUse hook and the `Issue Link` PR check enforce it; Dependabot and the `develop` -> `main` release merge are exempt.
- Changes to tenancy, authentication, tokens or data access need a PostgreSQL test and a `code-reviewer` pass before done.
