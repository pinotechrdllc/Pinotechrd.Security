# Architecture Decisions

This document captures the key architecture choices behind Pinotechrd.Security and why they were selected.

## ADR-001: Multi-tenant resolution trusts authenticated claims first

- Decision:
  For an authenticated principal the verified claim is the only tenant source; the header is never read for it, and a principal without the claim is rejected where a tenant is required. The `TenantId` header serves requests whose user is not authenticated when the middleware runs, and its value must be a well-formed tenant id that `ITenantStore` accepts. Because an endpoint can authenticate with its own schemes later, the middleware installs an endpoint feature that wraps every endpoint set on the request, and, after authorization, the wrapper rejects any authenticated user whose tenant claim differs from the resolved tenant. This was chosen over a separate middleware, a replaceable authorization service or a matcher policy registered in DI: it cannot be left out, replaced, or skipped by placing routing after the middleware, and it also covers re-executed endpoints. Tokens are issued only for the tenant resolved for the request. The JSON body and query string sources were removed after 1.2.0-preview.2: reading the body buffered it without a bound, and a query value ends up in logs and links.
- Why:
  Claims come from a validated token and are less spoofable than request metadata.
- Tradeoff:
  Requires correct middleware order (`UseAuthentication` before tenant resolution).
- Where:
  [Tenancy/TenantResolutionMiddleware.cs](../src/Pinotechrd.Security/Tenancy/TenantResolutionMiddleware.cs), [samples/Pinotechrd.Security.SampleApi/README.md](../samples/Pinotechrd.Security.SampleApi/README.md)

## ADR-002: Refresh tokens are opaque and stateful

- Decision:
  Refresh tokens are generated as opaque values and consumed server-side through a token store, in one atomic operation per refresh. Tokens rotated from one another form a family; presenting an already-consumed token revokes the family (RFC 9700, section 4.14.2).
- Why:
  Server-side validation allows revocation, replay protection, and rotation control.
- Tradeoff:
  Requires persistence and lifecycle management.
- Where:
  [src/Pinotechrd.Security.Abstractions/Interfaces/IRefreshTokenStore.cs](../src/Pinotechrd.Security.Abstractions/Interfaces/IRefreshTokenStore.cs), [Core/InMemoryRefreshTokenStore.cs](../src/Pinotechrd.Security/Core/InMemoryRefreshTokenStore.cs)

## ADR-003: Security checks are layered (subscription -> module -> permission)

- Decision:
  Access evaluation follows a strict hierarchy: active subscription, active module, then permission check.
- Why:
  This aligns entitlement billing with authorization outcomes and prevents bypassing module limits.
- Tradeoff:
  Slightly more evaluation steps per access check, mitigated with caching and store abstractions.
- Where:
  [Interfaces/ISecurityEngine.cs](../src/Pinotechrd.Security/Interfaces/ISecurityEngine.cs), [Core/SecurityEngine.cs](../src/Pinotechrd.Security/Core/SecurityEngine.cs)

## ADR-004: Release pipeline blocks risky packages and publishes without stored credentials

- Decision:
  CI and release workflows enforce vulnerability audit, warnings-as-errors build and coverage gates before NuGet push. Releases run only from `v*` tags on `main` and authenticate with nuget.org Trusted Publishing (short-lived OIDC-issued key). Author signing with a certificate was dropped in 1.2.0-preview.1 because nuget.org repository-signs every uploaded package.
- Why:
  Reduces supply-chain risk and increases trust for package consumers.
- Tradeoff:
  Slightly slower release cadence due to additional checks.
- Where:
  [.github/workflows/ci.yml](../.github/workflows/ci.yml), [.github/workflows/release.yml](../.github/workflows/release.yml)

## ADR-005: Tenant isolation comes from the database schema, in one of two explicit setups

- Decision:
  Tenant tables live in a schema per tenant; catalog tables live in one constant schema, with no foreign key from catalog to tenant tables. The context supports two setups, chosen with `UsePinotechrdSecurity`: the tenant's schema written into the EF Core model, with the model cache keyed by schema, or no schema in the model with the database `search_path` set per connection. In the first setup the context refuses to build its model when the cache is not keyed by schema. Module ids are derived from the module code (UUIDv5) so a plan in the catalog names the same module in every tenant.
- Why:
  EF Core caches one model per context type by default; with the schema in the model, every tenant silently got the first tenant's schema, and a user of that tenant could obtain tokens for others. Failing loudly is safer than a silent shared model. The `search_path` setup gives one model for all tenants, which suits migrations run per tenant.
- Tradeoff:
  Membership is only as strong as the setup: outside these two, the application must check it in `IIdentityValidator`. In the `search_path` setup the library binds every connection EF Core opens and checks every command, refuses connections opened inside an ambient transaction, and is PostgreSQL-only. The schema-in-model setup keeps one model per tenant, and EF Core holds only a bounded number of models; above about 40 active tenants the `search_path` setup is recommended.
- Where:
  [Data/PinotechrdSecurityDbContext.cs](../src/Pinotechrd.Security/Data/PinotechrdSecurityDbContext.cs), [Data/PinotechrdSecurityModelOptions.cs](../src/Pinotechrd.Security/Data/PinotechrdSecurityModelOptions.cs), [Core/SecurityCodes.cs](../src/Pinotechrd.Security/Core/SecurityCodes.cs)

## ADR-006: Release governance with a single maintainer

- Decision:
  `develop` and `main` require a pull request, an approving review from a code owner, the five CI checks (`validate`, CodeQL for C# and Actions, `dependency-review`, `issue-link`) up to date with the base, and forbid force pushes and deletion. `v*` tags can only be created by the admin role, and publishing runs only from a `v*` tag, in the `nuget-production` environment, after a required reviewer approves the deployment. The package is built once, attested (build provenance and SBOM) and pushed with Trusted Publishing, without stored credentials.
- Why:
  The repository has one maintainer, who is also the only code owner and the only reviewer of the environment. A rule that requires a second person (`prevent_self_review`, removing the admin bypass of the review) cannot be met and would block every release, so it is not configured: the admin role can merge a pull request without an approving review, and approves its own deployments. A setting that looks stricter but is always bypassed would only hide that fact.
- Tradeoff:
  One person can change and publish the package. The compensating controls are the ones that do not depend on a second person: required CI on every merge, CodeQL and dependency review, artifact attestations and SBOMs that let a consumer check that a package came from this repository's workflow and tag, and an independent review of security-relevant changes before a stable release. Every merge that bypasses review is visible in the pull request history.
- When this changes:
  With a second maintainer, add them to `CODEOWNERS`, turn on `prevent_self_review` for `nuget-production`, remove the admin bypass from the branch ruleset (keep it, if at all, only for emergencies with a documented reason), and require their approval for changes to tenancy, authentication, tokens, data access and the release workflow.
- Where:
  Repository rulesets "Protect develop and main" and "Protect release tags", environment `nuget-production`, [.github/CODEOWNERS](../.github/CODEOWNERS), [.github/workflows/release.yml](../.github/workflows/release.yml)
