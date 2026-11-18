# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project uses Semantic Versioning.

## [Unreleased]

### Removed (breaking)

- Tenant resolution no longer reads the JSON request body or the query string. `TenantResolutionOptions.JsonProperty` and `TenantResolutionOptions.QueryParameter` are gone. Reading the body buffered it with no size limit, and a query value ends up in logs and links. Send the tenant in the `TenantId` header (or the name set in `HeaderName`) on requests made before login.

### Changed (breaking)

- **Tenant resolution.** For an authenticated user the verified claim is the only source: the header is never read, whatever `Sources` says. An authenticated user without the claim is rejected with `tenant_invalid` on a path that requires a tenant. `Sources` now only decides whether anonymous requests may use the header.
- **Tenant resolution.** `RequiredPathPrefix` and `SkipPaths` match whole path segments, ignoring case: `/api` no longer matches `/apix`, and `/health` no longer skips `/healthcheck`.
- **Tenant ids.** A tenant id must be 1 to 56 characters from `a-z`, `0-9` and `-`, not starting with `-` (`TenantIdentifier`). Other values are rejected as `tenant_invalid` without calling `ITenantStore`, and `TenantContext.SetTenant` throws `ArgumentException` for them. Upper-case ids are rejected, not folded.
- **Schemas.** `TenantContext.SchemaName` is `tenant_` plus the id with `-` replaced by `_`, a mapping that no longer merges different ids. `DbSchemaProvider.GetSchemaName` throws when no tenant is resolved instead of falling back to the shared `identity` schema; set `TenantResolutionOptions.UseSharedSchemaWhenNoTenant` to keep the fallback (for example for design-time tooling).
- **JWT.** `Issuer` and `Audience` are required and always validated. The secret must be at least 32 bytes in UTF-8; `MinimumSecretLength` counts bytes and cannot go below 32. Only HMAC-SHA256 is accepted when validating tokens.
- **JWT.** `AddPinotechrdSecurity` no longer throws for missing or weak JWT settings. They are validated when the host starts (`ValidateOnStart`), and the host fails with an `OptionsValidationException` naming each setting.
- **Login.** `LoginAsync` returns `Invalid credentials` for a locked-out account too, instead of `Account locked out`, so the error does not tell which accounts exist. Lockout itself works as before.
- **Login.** `LoginAsync`, `VerifyTwoFactorCodeAsync` and `RefreshAsync` issue tokens only for the tenant resolved for the request (`TenantContext`). An unset tenant or a different `tenantId` is the generic failure. Before, the caller-supplied tenant went into the `tenant_id` claim unchecked.
- **Login.** Inactive users (`IsActive` false) can no longer log in, complete two-factor sign-in or refresh.
- **Two-factor.** `LoginAsync` now asks for the second factor when the user has two-factor enabled. Before, `CheckPasswordSignInAsync` never reported `RequiresTwoFactor`, so a password alone was enough.
- **Two-factor.** `AuthResult.TwoFactorToken` is now an opaque value protected with ASP.NET Core Data Protection, bound to the user, the tenant and the security stamp, and valid for five minutes. It used to be the user id, which anyone could send to `GetTwoFactorProvidersAsync`, `SendTwoFactorCodeAsync` and `VerifyTwoFactorCodeAsync`. A user id is no longer accepted by those methods.
- **Two-factor.** `VerifyTwoFactorCodeAsync` fails when `tenantId` is not the tenant the token was issued for, allows five attempts per token, counts a wrong code toward lockout, refuses locked-out users before and after checking the code, rejects providers the user does not have, and renews the security stamp on success, which invalidates the token.
- **Two-factor.** `SendTwoFactorCodeAsync` refuses locked-out users and answers an unknown provider with a failure instead of an exception.
- **Refresh tokens.** `IRefreshTokenStore` gains `ConsumeAsync` (atomic validate and invalidate, with reuse detection by token family) and `RevokeAllForUserAsync`. `SaveAsync` gains `familyId` and `securityStamp`, and every method takes a `CancellationToken`. Existing implementations must add the new members. A default interface method could not make consumption atomic, so none is provided.
- **Refresh tokens.** `RefreshAsync` consumes the token atomically, refuses a token of another tenant without consuming it, and checks that the user exists, is active, is not locked out, may sign in, and still has the security stamp it had when the token was issued. Every failure is `Invalid token`; the store's reason is no longer returned.
- **Sign-out.** `SignOutAsync` revokes all refresh tokens of the user as well as renewing the security stamp. Access tokens stay valid until they expire.
- **Users.** `SetUserActiveStatusAsync(userId, false)` revokes the user's refresh tokens and renews its security stamp.
- `ResetPasswordAsync` answers an unknown e-mail with the same failure as an invalid reset token, instead of `User not found`.
- `PinotechrdAuthManager<TUser>` requires `TUser` to have a public parameterless constructor (`new()`). `AddPinotechrdSecurity` already required it.

### Added

- `TenantResolutionOptions.Sources`, `OnMissingTenant` (`MissingTenantBehavior.Reject` by default, or `Continue` so an anonymous caller of a protected endpoint gets `401`), `RequiredPathPrefix` (default `/api`, replaces the hard-coded prefix) and `UseSharedSchemaWhenNoTenant`.
- `TenantIdentifier` (`IsValid`, `ToSchemaName`, `MaxLength`, `SchemaPrefix`).
- Tenant rejections go through `IProblemDetailsService` when the application registers one, as `application/problem+json` with a `code` member (`tenant_required` or `tenant_invalid`, see `TenantResolutionErrorCodes`). Without it the plain-text body is unchanged.
- `UseTenantResolution()` throws `InvalidOperationException` when an authentication scheme is configured but `UseAuthentication()` has not run before it. Hosts without authentication are not affected.
- `ITwoFactorAttemptStore` and its default `InMemoryTwoFactorAttemptStore`, registered by `AddPinotechrdSecurity`.
- `RefreshTokenConsumeResult` and `RefreshTokenConsumeStatus`. `InMemoryRefreshTokenStore` and `InMemoryTwoFactorAttemptStore` accept a `TimeProvider`.
- `PinotechrdAuthManager<TUser>` takes optional `IDataProtectionProvider`, `TenantContext`, `ITwoFactorAttemptStore` and `TimeProvider`. Without a `TenantContext` every login and refresh fails; without the first two of the others, two-factor sign-in fails closed. `PinotechrdSecurityManager<TUser, TRole>` takes an optional `IRefreshTokenStore`.

### Security

- Login for an unknown or inactive user, a user without a password, a locked-out user, a user Identity does not allow to sign in, or a tenant mismatch verifies the password against a dummy hash, so the response time reveals less about which accounts exist. It is not constant time. The dummy hash is made once per password hasher type.
- An unknown, an inactive and a malformed tenant get the same status and body.

## [1.2.0-preview.2] - 2026-11-17

### Changed (breaking)

- **Renamed** every public type and method from the `Pinotech` prefix to `Pinotechrd`, to match the package and namespace names:

  | Before | After |
  | --- | --- |
  | `AddPinotechSecurity` | `AddPinotechrdSecurity` |
  | `PinotechSecurityOptions` | `PinotechrdSecurityOptions` |
  | `PinotechSecurityDbContext<TUser, TRole>` | `PinotechrdSecurityDbContext<TUser, TRole>` |
  | `IPinotechAuthManager<TUser>` / `PinotechAuthManager<TUser>` | `IPinotechrdAuthManager<TUser>` / `PinotechrdAuthManager<TUser>` |
  | `IPinotechSecurityManager<TUser, TRole>` / `PinotechSecurityManager<TUser, TRole>` | `IPinotechrdSecurityManager<TUser, TRole>` / `PinotechrdSecurityManager<TUser, TRole>` |
  | `IPinotechMessageService` | `IPinotechrdMessageService` |

### Removed (breaking)

- `Tenant.NcfMode`, `Tenant.NcfPrefix`, `Tenant.DgiiApiKey`, `Tenant.DgiiApiUrl`, `Tenant.ConfigureNcf` and the `NcfMode` enum. Fiscal document settings are not a security concern; keep them in the host application. Applications that mapped these columns need a migration that moves or drops them.

### Added

- `GetActiveCatalogAsync` returns the modules on a tenant's active plan, each with its active permissions. A module outside the plan is absent.
- `GetUserOverridesAsync` and `ReplaceUserOverridesAsync` read and replace a user's Allow and Deny rows. An empty list clears them. Deny wins when both are sent for one code.
- The effective permission set is the role bundle, plus Allow, minus Deny. `CanAccessAsync` and `GetPermissionsAsync` use it. A full `Module.Permission` code matches only that module. A bare permission name still matches.

### Changed

- The plan catalog and the user overrides are not kept in the fifteen-minute security cache.

## [1.2.0-preview.1] - 2026-11-17

First release under the new name. Nothing was ever published to nuget.org under the old
names (`PinotechSecurity`, `Pinotech.Security.Abstractions`); they only existed as local packages.

### Changed (breaking)

- **Renamed** packages, assemblies and root namespaces:

  | Before | After |
  | --- | --- |
  | Package `PinotechSecurity` | `Pinotechrd.Security` |
  | Package `Pinotech.Security.Abstractions` | `Pinotechrd.Security.Abstractions` |
  | Namespace `Pinotech.Security.*` | `Pinotechrd.Security.*` |

  Public type and method names (`AddPinotechSecurity`, `PinotechSecurityOptions`,
  `IPinotechAuthManager`, ...) are unchanged.
- `Pinotechrd.Security` depends on `Pinotechrd.Security.Abstractions` with the same version.
- Microsoft.* dependencies updated from 10.0.6 to 10.0.15.

### Migration

1. Replace the package references:
   `PinotechSecurity` → `Pinotechrd.Security`, `Pinotech.Security.Abstractions` → `Pinotechrd.Security.Abstractions`, version `1.2.0-preview.1`.
2. Replace `using Pinotech.Security` with `using Pinotechrd.Security` (and any fully qualified `Pinotech.Security.` names).

### Build and release

- Repository reorganized into `src/`, `tests/` and `samples/`; solution is `Pinotechrd.Security.slnx`.
- Shared metadata in `Directory.Build.props`, package versions in `Directory.Packages.props` (Central Package Management), `global.json` and `.editorconfig` added.
- License declared as the `MIT` expression in both packages; README included in both.
- Source Link now comes from the .NET SDK; the explicit `Microsoft.SourceLink.GitHub` 8.0.0 reference
  (which pulled vulnerable `Microsoft.Build.Tasks.Git` 8.0.0, GHSA-23fw-v26w-5fgq) was removed.
- Library projects build with warnings as errors, track their public API with
  `Microsoft.CodeAnalysis.PublicApiAnalyzers` and enable package validation.
- Releases are published only from `v*` tags through nuget.org Trusted Publishing (no stored API key).
  Author signing with a certificate was removed; nuget.org repository-signs every uploaded package.

## [1.1.0] - 2026-07-21

### Added

- **Fase 2: hierarchical security engine.** `Core/SecurityEngine.cs` implements
  `ISecurityEngine` and evaluates access in three layers — Suscripción → Módulo
  → Permiso — via `ISecurityStore` (subscription + module state) and
  `ISecurityDataProvider` (user identity + permissions). Exposes:
  - `CanAccessAsync(moduleCode, permissionName)` for ad-hoc checks
  - `GetAuthorizedMenuAsync(fullMenu)` for the recursive filter used by the
    auth login response, with N+1-avoidance via `ToFrozenSet<string>` for the
    module + permission lookups
  - `GetPermissionsAsync(userId)` for the full permission set (filtered by
    active modules in the future if needed)
- **Fase 2.2: `Core/TenantCacheStore.cs`** decorator of `ISecurityStore` that
  adds an `IMemoryCache` layer (15-minute default expiration) around
  `IsSubscriptionActiveAsync`, `IsModuleActiveAsync`, and
  `GetActiveModuleCodesAsync`. Cache keys are scoped per tenant
  (`security:subscription:{tenantId}`, `security:module:{tenantId}:{moduleCode}`,
  `security:modules:codes:{tenantId}`) so multi-tenant blast radius is zero.
- **`Authorization/PermissionRequirement`** parses the `Module.Permission`
  format into `FullName`, `ModuleCode`, and `Permission` so ASP.NET Core
  authorization policies can express fine-grained requirements.
- **`Authorization/PermissionAuthorizationHandler`** evaluates the
  `PermissionRequirement` against the current user's `ISecurityEngine`
  results, so `[Authorize(Policy = "Orders.View")]` now respects the
  full Suscripción → Módulo → Permiso hierarchy.
- **`Extensions/AddPinotechSecurity()`** extension is now the single
  entry point that wires the engine, the cache decorator, and the
  authorization handler in the correct order. DI consumers no longer
  need to register each piece individually.

### Changed

- The `AddPinotechSecurity<TContext, TUser, TRole>` overload now requires
  the consumer to register an `ISecurityStore` implementation (or accept
  the default no-op store). The library no longer assumes the database
  layout — that decision is delegated to the consumer.
- `ISecurityDataProvider` contract is unchanged (an
  existing implementation keeps working).

### Upgrade Notes

- Consumers must register an `ISecurityStore`
  implementation that bridges their permission/subscription data to
  the new `IsSubscriptionActiveAsync` / `IsModuleActiveAsync` /
  `GetActiveModuleCodesAsync` contract. The library no longer auto-discovers
  the schema.
- Consumers that want cache-backed validation must register
  `services.AddMemoryCache()` before `AddPinotechSecurity()` (the
  handler is a decorator that requires `IMemoryCache` in DI).

## [1.0.0] - 2026-05-09

### Added

- Initial production-readiness baseline for coordinated NuGet publishing.
- CI workflow with test and packaging validation.
- Publish workflow for tag/manual release.
- Centralized package version policy via Directory.Build.props.
- Coverage gate enforcement in CI (`>= 70%`).
- Release hardening checks (version consistency and required changelog section).
- Rollback runbook for NuGet incidents.
- Executable sample API for package consumption.
- Public repository governance documents (`SECURITY.md`, `CONTRIBUTING.md`).
- Refresh token opaque lifecycle baseline (`IRefreshTokenStore`, in-memory implementation, rotation + revocation).
- NuGet vulnerability audit gates in CI and publish workflows (High/Critical fail policy).
- NuGet package signing and verification stage in publish workflow.
- Dependabot automation for NuGet and GitHub Actions dependencies.

### Changed

- Package messaging aligned to .NET 10 only.
- Abstractions package messaging aligned to Identity extension scenarios.
- NuGet metadata consistency improved for both packages.
- Tenant resolution now prioritizes authenticated claim source and no longer parses unsigned bearer payloads.
- Expired-token principal extraction now validates issuer/audience when configured.
- JWT secret policy enforces minimum length via startup and token provider guards.

### Security Advisory Notes

- Behavioral hardening: refresh tokens are validated server-side as opaque values and rotated on successful refresh.
- Behavioral hardening: weak JWT secrets now fail fast during service registration/startup.
- Behavioral hardening: tenant context must come from authenticated principal (fallback sources apply only when claim is unavailable).
- Consumer impact: systems relying on lax token/tenant behavior should validate startup config and refresh integration before rollout.
