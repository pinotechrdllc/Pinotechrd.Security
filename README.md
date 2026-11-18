# Pinotechrd.Security

[![CI](https://github.com/pinotechrdllc/Pinotechrd.Security/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/pinotechrdllc/Pinotechrd.Security/actions/workflows/ci.yml)
[![CodeQL](https://github.com/pinotechrdllc/Pinotechrd.Security/actions/workflows/codeql.yml/badge.svg?branch=develop)](https://github.com/pinotechrdllc/Pinotechrd.Security/actions/workflows/codeql.yml)
[![NuGet Pinotechrd.Security](https://img.shields.io/nuget/vpre/Pinotechrd.Security.svg)](https://www.nuget.org/packages/Pinotechrd.Security)
[![NuGet Pinotechrd.Security.Abstractions](https://img.shields.io/nuget/vpre/Pinotechrd.Security.Abstractions.svg)](https://www.nuget.org/packages/Pinotechrd.Security.Abstractions)

Multi-tenant identity and authorization infrastructure for ASP.NET Core on .NET 10: granular permissions, tenant resolution and hardened JWT authentication.

> **Preview.** The public API can still change before 1.2.0 is released. See the [changelog](https://github.com/pinotechrdllc/Pinotechrd.Security/blob/develop/CHANGELOG.md).

## Features

- **Tenant resolution** from the authenticated claim, or from a header when there is no claim.
- **Permission-based authorization**: any `[Authorize(Policy = "Module.Permission")]` is checked against the tenant's subscription, its active modules, and the user's roles and overrides.
- **ASP.NET Core Identity** wired with JWT bearer authentication and password and e-mail defaults.
- **JWT access tokens and opaque refresh tokens** with server-side validation and rotation.
- **Packaging**: SourceLink, deterministic builds, XML documentation and symbol packages (`.snupkg`).

## Packages

| Package | Target | Use it when |
| --- | --- | --- |
| `Pinotechrd.Security` | net10.0 | You want the full stack: identity, JWT, tenancy and authorization. This is the default choice. |
| `Pinotechrd.Security.Abstractions` | net10.0 | You only need the entities and interfaces, without the runtime services. |

`Pinotechrd.Security` already depends on `Pinotechrd.Security.Abstractions`; you do not need to install both.

## Installation

Only preview versions are published, so the `--prerelease` flag is required:

```bash
dotnet add package Pinotechrd.Security --prerelease
```

## Quick Start

### 1. What your application provides

| You provide | Requirement |
| --- | --- |
| A user and a role type | Derive from `BaseSecurityUser` and `BaseSecurityRole`. |
| An EF Core `DbContext` | Implement `ISecurityDbContext`, or derive from `PinotechrdSecurityDbContext<TUser, TRole>`. |
| `ITenantStore` | Tells the middleware whether a tenant id exists. Not registered by default. |
| `ISecurityDataProvider` | Supplies the current user, tenant, roles and permissions to the permission engine. Not registered by default. |

### 2. Register the services

```csharp
using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppSecurityDbContext>(options =>
    options.UseInMemoryDatabase("security"));

builder.Services.AddPinotechrdSecurity<AppSecurityDbContext, AppUser, AppRole>(options =>
{
    // Read the secret from configuration or a secret store. Never commit it.
    options.Jwt.Secret = builder.Configuration["Security:JwtSecret"]!;
    options.Jwt.Issuer = "my-api";
    options.Jwt.Audience = "my-api-clients";

    options.Tenancy.SkipPaths.Add("/health");
});

builder.Services.AddScoped<ITenantStore, AppTenantStore>();
builder.Services.AddScoped<ISecurityDataProvider, AppSecurityDataProvider>();
```

`AppSecurityDbContext`, `AppUser`, `AppRole`, `AppTenantStore` and `AppSecurityDataProvider` are your own types. The [sample API](https://github.com/pinotechrdllc/Pinotechrd.Security/tree/develop/samples/Pinotechrd.Security.SampleApi) contains a complete, runnable version of each.

### 3. Configure the middleware

```csharp
var app = builder.Build();

app.UseAuthentication();
app.UseTenantResolution();
app.UseAuthorization();
```

Keep `UseAuthentication()` before `UseTenantResolution()`, so the tenant claim comes from a validated principal. When an authentication scheme is configured and `UseTenantResolution()` runs first, the first anonymous request throws `InvalidOperationException` naming the required order, instead of trusting the header. A host with no authentication scheme at all is not affected.

### 4. Protect an endpoint

```csharp
[Authorize(Policy = "Users.View")]
public IActionResult GetUsers() => Ok();
```

The policy name is `Module.Permission`: `Users.View` checks the `View` permission of the `Users` module. A name without a dot is checked against the `Global` module. Policies you register yourself with `AddAuthorization` keep working as usual.

## Configuration Reference

### JWT (`options.Jwt`)

| Option | Default | Notes |
| --- | --- | --- |
| `Secret` | none | Required. At least 32 bytes in UTF-8. |
| `MinimumSecretLength` | `32` | Minimum length of `Secret` in UTF-8 bytes. Can be raised, not lowered below 32. |
| `Issuer` | not set | Required. Always validated. |
| `Audience` | not set | Required. Always validated. |
| `ExpiryMinutes` | `60` | Access token lifetime. |
| `RefreshTokenExpiryDays` | `7` | Refresh token lifetime. |

The JWT settings are checked when the host starts, not inside `AddPinotechrdSecurity`, so tools that build the host without configuration (such as OpenAPI generation at build time) still work. A missing or weak setting makes the host fail to start with an `OptionsValidationException` that names the setting, for example `PinotechrdSecurityOptions.Jwt.Secret`. Tokens are signed with HMAC-SHA256, and only that algorithm is accepted when they are validated.

### Tenant resolution (`options.Tenancy`)

Where the tenant id comes from depends on whether the request is authenticated:

| Request | Source | Option | Default |
| --- | --- | --- | --- |
| Authenticated | Claim of the user, and nothing else | `ClaimType` | `tenant_id` |
| Anonymous | Request header | `HeaderName` | `TenantId` |

For an authenticated user the header is never read, so a header naming another tenant is ignored and does not cause a rejection. An authenticated user without the claim is rejected with `tenant_invalid` on a path that requires a tenant, whatever `OnMissingTenant` says; on other paths it continues without a tenant. The header serves anonymous requests such as login and refresh. The JSON body and the query string are not read.

| Option | Default | Notes |
| --- | --- | --- |
| `Sources` | `Claim \| Header` | Decides only what anonymous requests may use. Without `Header`, anonymous requests have no tenant. The claim is always used for authenticated users and cannot be turned off, so `Header` alone behaves like the default. |
| `OnMissingTenant` | `Reject` | `Reject` answers `400` when an anonymous request that requires a tenant has none. `Continue` lets it through without a tenant, so authorization can answer `401` to an anonymous caller of a protected endpoint. |
| `RequiredPathPrefix` | `/api` | Requests under this prefix require a tenant. Matching is by whole path segments, ignoring case: `/api` covers `/api` and `/api/orders`, not `/apix`. `/` means every path; empty means none. |
| `SkipPaths` | empty | Requests under one of these prefixes bypass tenant resolution. Matched by whole segments too: `/health` does not skip `/healthcheck`. |
| `UseSharedSchemaWhenNoTenant` | `false` | See [Tenant ids and schemas](#tenant-ids-and-schemas). |

- A tenant id that is malformed or that `ITenantStore` does not recognize is rejected with `400 Bad Request`, whatever `OnMissingTenant` says. A malformed id never reaches `ITenantStore`. An unknown tenant and an inactive one get the same answer.
- When the application registers `IProblemDetailsService` (for example with `builder.Services.AddProblemDetails()`), rejections are `application/problem+json` with a `code` member: `tenant_required` or `tenant_invalid` (constants in `TenantResolutionErrorCodes`). Without it, the body is plain text.
- Tenant ids and header values are not logged.

### Tenant ids and schemas

- A tenant id is 1 to 56 characters from `a-z`, `0-9` and `-`, and does not start with `-` (`TenantIdentifier.IsValid`). Lower-case GUIDs qualify. Upper case is rejected, not folded.
- The schema of a tenant is `tenant_` plus the id with `-` replaced by `_` (`TenantIdentifier.ToSchemaName`). Two different ids never share a schema, and the longest name is 63 characters, the PostgreSQL limit.
- `DbSchemaProvider` throws when no tenant is resolved, instead of falling back to the shared `identity` schema. Set `options.Tenancy.UseSharedSchemaWhenNoTenant = true` only where no tenant is expected, such as design-time tooling.

### Login and two-factor

- Tokens are issued only for the tenant the request was resolved for. `LoginAsync`, `VerifyTwoFactorCodeAsync` and `RefreshAsync` fail when no tenant is resolved or when the `tenantId` passed in differs from it. With one schema per tenant, the user is looked up in that tenant's schema, so finding the user proves it belongs to the tenant. With a shared schema, check membership in an `IIdentityValidator<TUser>`.
- `LoginAsync` returns the same failure, `Invalid credentials`, for an unknown user, an inactive user (`IsActive` false), a wrong password, a user without a password, a locked-out account, an account Identity does not allow to sign in, and a tenant mismatch. Lockout works as in ASP.NET Core Identity.
- On every path where Identity would not hash the password against a stored hash (unknown, inactive, locked out, not allowed, no password, tenant mismatch), the password is checked against a dummy hash made once with the same hasher. This makes it harder to tell from the response time whether an account exists. It does not make the response time constant.
- When the user has two-factor enabled, `LoginAsync` returns `RequiresTwoFactor` and a `TwoFactorToken`. That answer shows the password was right, as in every two-step login. The token is opaque, protected with ASP.NET Core Data Protection, bound to the user, the tenant and the security stamp, and valid for five minutes. Pass it to `GetTwoFactorProvidersAsync`, `SendTwoFactorCodeAsync` and `VerifyTwoFactorCodeAsync`, with the same tenant as the login.
- Each token allows five code attempts, counted through `ITwoFactorAttemptStore` before the code is checked, so concurrent guesses count too. Wrong codes also count toward Identity lockout, and locked-out users are refused. The default `InMemoryTwoFactorAttemptStore` keeps counts per instance: with several instances, register a shared implementation.
- A successful verification renews the security stamp, which makes the token single use. This depends on a user store that keeps security stamps and detects concurrent updates (the EF Core store does). Renewing the stamp also invalidates pending password reset and e-mail confirmation tokens. E-mail and SMS codes depend on the stamp; authenticator-app codes do not, so with an authenticator the same code stays valid for its time window, though not with the same token.
- `SendTwoFactorCodeAsync` accepts only providers the user has, and sends a message every time it succeeds. Rate limit it in your API.
- In a deployment with several instances, Data Protection keys must be shared between them, or a token issued by one instance is rejected by another.
- `ResetPasswordAsync` answers an unknown e-mail with the same failure as an invalid reset token.

### Refresh tokens and sign-out

- Refresh tokens are opaque values kept through `IRefreshTokenStore`. `RefreshAsync` consumes the presented token atomically: of two concurrent refreshes with one token, exactly one succeeds.
- Tokens issued by rotating one another form a family. Presenting a token that was already used revokes the whole family (RFC 9700, section 4.14.2), so a client that sends two refreshes at once loses that session.
- A token of another tenant is refused without being consumed. The user must still exist, be active, not be locked out, be allowed to sign in, and have the security stamp it had when the token was issued. Every failure returns `Invalid token`.
- `SignOutAsync` revokes all refresh tokens of the user, in every session, and renews the security stamp. Deactivating a user with `SetUserActiveStatusAsync(userId, false)` does the same.
- Access tokens already issued stay valid until they expire (`ExpiryMinutes`, 60 by default): JWT validation does not ask the server. Keep `ExpiryMinutes` short if that window matters.
- The default `InMemoryRefreshTokenStore` loses tokens on restart and does not share them between instances. Register your own `IRefreshTokenStore` after `AddPinotechrdSecurity` for production. Its `ConsumeAsync` must be atomic (for example a single conditional `UPDATE ... WHERE consumed = false` that reports the affected rows); a read followed by a write lets two concurrent refreshes through.

## Sample API

The [sample API](https://github.com/pinotechrdllc/Pinotechrd.Security/tree/develop/samples/Pinotechrd.Security.SampleApi) shows token issuing, refresh rotation and tenant resolution. From a clone of the repository:

```bash
dotnet run --project samples/Pinotechrd.Security.SampleApi/Pinotechrd.Security.SampleApi.csproj
curl -H "TenantId: demo" http://localhost:5000/api/tenant
```

## Quality and Security Checks

Every pull request runs the build with warnings as errors, a vulnerability audit of dependencies, the test suite with a minimum line-coverage gate, CodeQL static analysis, a dependency review and package validation of the public API. Releases are tag-driven and published with nuget.org Trusted Publishing, so no API key is stored in the repository.

## Project Links

- [Changelog](https://github.com/pinotechrdllc/Pinotechrd.Security/blob/develop/CHANGELOG.md)
- [Security policy](https://github.com/pinotechrdllc/Pinotechrd.Security/blob/develop/SECURITY.md)
- [Contribution guide](https://github.com/pinotechrdllc/Pinotechrd.Security/blob/develop/CONTRIBUTING.md)
- [Architecture decisions](https://github.com/pinotechrdllc/Pinotechrd.Security/blob/develop/docs/ARCHITECTURE_DECISIONS.md)
- Maintainers: [publishing guide](https://github.com/pinotechrdllc/Pinotechrd.Security/blob/develop/docs/NUGET_PUBLISH_STEP_BY_STEP.md) and [rollback procedure](https://github.com/pinotechrdllc/Pinotechrd.Security/blob/develop/docs/ROLLBACK.md)

## License

Distributed under the [MIT License](https://github.com/pinotechrdllc/Pinotechrd.Security/blob/develop/LICENSE).
