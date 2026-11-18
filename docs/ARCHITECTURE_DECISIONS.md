# Architecture Decisions

This document captures the key architecture choices behind Pinotechrd.Security and why they were selected.

## ADR-001: Multi-tenant resolution trusts authenticated claims first

- Decision:
  For an authenticated principal the verified claim is the only tenant source; the header is never read for it, and a principal without the claim is rejected where a tenant is required. The `TenantId` header serves anonymous requests only, and its value must be a well-formed tenant id that `ITenantStore` accepts. Tokens are issued only for the tenant resolved for the request. The JSON body and query string sources were removed after 1.2.0-preview.2: reading the body buffered it without a bound, and a query value ends up in logs and links.
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
