# Architecture Decisions

This document captures the key architecture choices behind Pinotechrd.Security and why they were selected.

## ADR-001: Multi-tenant resolution trusts authenticated claims first

- Decision:
  Tenant resolution uses authenticated user claims as the primary source, then falls back to the `TenantId` header only when the claim is not available. A header never overrides the claim. The JSON body and query string sources were removed after 1.2.0-preview.2: reading the body buffered it without a bound, and a query value ends up in logs and links.
- Why:
  Claims come from a validated token and are less spoofable than request metadata.
- Tradeoff:
  Requires correct middleware order (`UseAuthentication` before tenant resolution).
- Where:
  [Tenancy/TenantResolutionMiddleware.cs](../src/Pinotechrd.Security/Tenancy/TenantResolutionMiddleware.cs), [samples/Pinotechrd.Security.SampleApi/README.md](../samples/Pinotechrd.Security.SampleApi/README.md)

## ADR-002: Refresh tokens are opaque and stateful

- Decision:
  Refresh tokens are generated as opaque values and validated server-side through a token store.
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
