# Pinotechrd.Security

[![CI](https://github.com/pinotechrdllc/Pinotechrd.Security/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/pinotechrdllc/Pinotechrd.Security/actions/workflows/ci.yml)
[![CodeQL](https://github.com/pinotechrdllc/Pinotechrd.Security/actions/workflows/codeql.yml/badge.svg?branch=develop)](https://github.com/pinotechrdllc/Pinotechrd.Security/actions/workflows/codeql.yml)
[![NuGet Pinotechrd.Security](https://img.shields.io/nuget/vpre/Pinotechrd.Security.svg)](https://www.nuget.org/packages/Pinotechrd.Security)
[![NuGet Pinotechrd.Security.Abstractions](https://img.shields.io/nuget/vpre/Pinotechrd.Security.Abstractions.svg)](https://www.nuget.org/packages/Pinotechrd.Security.Abstractions)

Multi-tenant identity and authorization infrastructure for ASP.NET Core on .NET 10: granular permissions, tenant resolution and hardened JWT authentication.

> **Preview.** The public API can still change before 1.2.0 is released. See the [changelog](https://github.com/pinotechrdllc/Pinotechrd.Security/blob/develop/CHANGELOG.md).

## Features

- **Tenant resolution** from the authenticated claim, a header, the JSON body or the query string.
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

Keep `UseAuthentication()` before `UseTenantResolution()`, so the tenant claim comes from a validated principal.

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
| `Secret` | none | Required. Startup fails if it is empty or shorter than `MinimumSecretLength`. |
| `MinimumSecretLength` | `32` | Minimum accepted length of `Secret`. |
| `Issuer` | not set | Validated only when set. |
| `Audience` | not set | Validated only when set. |
| `ExpiryMinutes` | `60` | Access token lifetime. |
| `RefreshTokenExpiryDays` | `7` | Refresh token lifetime. |

### Tenant resolution (`options.Tenancy`)

The tenant id is taken from the first source that has a value, in this order:

| Order | Source | Option | Default |
| --- | --- | --- | --- |
| 1 | Claim of the authenticated user | `ClaimType` | `tenant_id` |
| 2 | Request header | `HeaderName` | `TenantId` |
| 3 | JSON request body property | `JsonProperty` | `tenantId` |
| 4 | Query string parameter | `QueryParameter` | `tenantId` |

- A tenant id that `ITenantStore` does not recognize is rejected with `400 Bad Request`.
- A request to a path starting with `/api` with no tenant id is rejected with `400 Bad Request`.
- Paths starting with a prefix in `SkipPaths` bypass tenant resolution.

### Refresh tokens

Refresh tokens are opaque values validated through `IRefreshTokenStore`. The default registration is `InMemoryRefreshTokenStore`: tokens are lost on restart and are not shared between instances. Register your own `IRefreshTokenStore` after `AddPinotechrdSecurity` for production or multi-instance deployments.

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
