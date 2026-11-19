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
dotnet add package Npgsql.EntityFrameworkCore.PostgreSQL   # the database provider used below
```

## Quick Start

### 1. What your application provides

| You provide | Requirement |
| --- | --- |
| A user and a role type | Derive from `BaseSecurityUser` and `BaseSecurityRole`. |
| An EF Core `DbContext` | Derive from `PinotechrdSecurityDbContext<TUser, TRole>`, with the constructor `(DbContextOptions<T> options, ISchemaProvider schemaProvider) : base(options, schemaProvider)`. |
| `ITenantStore` | Tells the middleware whether a tenant id exists and is active. It runs before the tenant is resolved, so it must read the catalog directly, not through the tenant context. Not registered by default. |
| `ISecurityDataProvider` | Supplies the permission engine with the current user id, the current tenant, and roles and permissions. The user id is the `id` claim that `LoginAsync` writes. The tenant is the one whose data the provider reads (`TenantContext.TenantId`). Permissions must be full `MODULE.PERMISSION` codes such as `SALES.VIEW`. Not registered by default. |

```csharp
public sealed class AppSecurityDbContext : PinotechrdSecurityDbContext<AppUser, AppRole>
{
    public AppSecurityDbContext(DbContextOptions<AppSecurityDbContext> options, ISchemaProvider schemaProvider)
        : base(options, schemaProvider)
    {
    }
}

public sealed class AppSecurityDataProvider(
    IHttpContextAccessor http, TenantContext tenant, IPinotechrdSecurityManager<AppUser, AppRole> security) : ISecurityDataProvider
{
    public string? GetCurrentUserId() => http.HttpContext?.User.FindFirstValue("id");
    public string? GetCurrentTenantId() => tenant.TenantId;
    public Task<IEnumerable<string>> GetUserRolesAsync(string userId) => security.GetUserRolesAsync(userId);

    public async Task<IEnumerable<string>> GetUserPermissionsAsync(string userId)
    {
        var codes = new List<string>();
        foreach (var name in await security.GetUserRolesAsync(userId))
        {
            if (await security.GetRoleByNameAsync(name) is { } role)
                codes.AddRange(await security.GetRolePermissionsAsync(role.Id.ToString()));
        }
        return codes; // full MODULE.PERMISSION codes
    }
}

public sealed class AppTenantStore(NpgsqlDataSource dataSource) : ITenantStore // register: AddSingleton(NpgsqlDataSource.Create(cs))
{
    public async Task<bool> TenantExistsAsync(string tenantId)
    {
        await using var command = dataSource.CreateCommand(
            "SELECT EXISTS (SELECT 1 FROM public.tenants WHERE \"Identifier\" = $1 AND \"Status\" = $2)");
        command.Parameters.Add(new NpgsqlParameter { Value = tenantId });
        command.Parameters.Add(new NpgsqlParameter { Value = (int)TenantStatus.Active });
        return (bool)(await command.ExecuteScalarAsync())!;
    }
}
```

### 2. Register the services

```csharp
using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddScoped<ISchemaProvider, DbSchemaProvider>();
builder.Services.AddDbContext<AppSecurityDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("Security"))
           .UsePinotechrdSecurity()); // required: see "Database schemas"

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

Keep `UseAuthentication()` before `UseTenantResolution()`, so the tenant claim comes from a validated principal. When an authentication scheme is configured and `UseTenantResolution()` runs first, the first unauthenticated request throws `InvalidOperationException` naming the required order, instead of trusting the header. A host with no authentication scheme at all is not affected.

**Tenant consistency check.** An endpoint can authenticate with its own schemes (`[Authorize(AuthenticationSchemes = "...")]`) after the tenant was already taken from the header. So, before any endpoint of the request runs, any authenticated user must carry exactly one tenant claim equal to the resolved tenant; otherwise the request gets `400` with code `tenant_invalid` and the endpoint does not run.

- The check runs after authorization has added the endpoint's schemes to `HttpContext.User`.
- It does not depend on where `UseRouting()` is: the middleware installs its own endpoint feature, which wraps every endpoint that routing (before or after it) or a re-execution (exception handler, status code pages) sets on the request.
- This covers minimal APIs, MVC controllers, Razor Pages and fallback endpoints, with or without `[AllowAnonymous]`.
- Skip paths are not checked. A URL rewrite that runs after `UseTenantResolution()` can turn a skip path into a required one without the check: place `UseRewriter()` (and anything else that changes the path) before `UseTenantResolution()`.
- Endpoints marked `ShortCircuit()` run inside routing, before authorization and before the endpoint middleware, so they get neither authorization nor this check. Do not short-circuit tenant-scoped endpoints.

Not covered by the check:

- Code inside an endpoint that calls `AuthenticateAsync` itself. Compare the claim with `TenantContext` yourself there.
- Long-lived connections such as SignalR, which are checked only when they connect. See [Known limits](#before-a-stable-release-known-limits).

### 4. Protect an endpoint

```csharp
[Authorize(Policy = "Users.View")]
public IActionResult GetUsers() => Ok();
```

The policy name is `Module.Permission`: `Users.View` requires the permission code `USERS.VIEW`. A name without a dot is the permission of the `GLOBAL` module: `Admin` requires `GLOBAL.ADMIN`. Only the full code grants access; a bare permission name such as `VIEW` no longer matches every module. Policies you register yourself with `AddAuthorization` keep working as usual.

Codes are 1 to 100 characters from `A-Z a-z 0-9 _ . -`. They are compared after trimming and upper-casing, as they are stored, so `Users.View` and `USERS.VIEW` are the same. Other characters are rejected, not folded: the seeder, `AssignPermissionsToRoleAsync` and `ReplaceUserOverridesAsync` refuse them, and a policy name with them throws `ArgumentException`. `AssignPermissionsToRoleAsync` also returns `false`, changing nothing, when a code names a permission that does not exist.

Before the permission is checked, the authenticated user's tenant claim must equal the tenant resolved for the request; a missing claim, two different tenant claims, no resolved tenant, or a difference fails the policy.

The engine trusts one tenant:

- For an HTTP request with an authenticated user, it is the user's tenant claim, which must also equal `TenantContext`.
- Otherwise (anonymous requests, background work) it is `TenantContext`; background work must call `TenantContext.SetTenant` first.
- It denies when `ISecurityDataProvider.GetCurrentTenantId()`, the tenant whose data your provider reads, is not that tenant.

### 5. Seed and provision

**Every permission check answers `403` until the database holds all of the following:**

- the catalog tables;
- the tenant's own tables;
- the modules and full permission codes;
- a role with those permissions, and a user in that role;
- a plan whose plan-module rows use `SecurityModuleId.FromCode`;
- a subscription whose tenant name is the tenant id and whose start date is today or earlier;
- an active tenant row.

The method below creates all of these for one tenant. It works in both schema modes, with the context registered with `ExcludeCatalogFromMigrations = true`. Call it with `createCatalog: true` for the first tenant only: that call creates the catalog tables, through a context configured like yours but with the catalog included. Nothing else creates them while the registered context excludes the catalog. It was tested on PostgreSQL 17.7 in both modes: login answered 200, `[Authorize(Policy = "Sales.View")]` answered 200, a missing permission 403, and a user logging in to another tenant 401.

```csharp
public static async Task ProvisionTenantAsync(IServiceProvider services, string connectionString, TenantSchemaMode mode,
    string tenantId, string customerName, string adminEmail, string adminPassword, bool createCatalog)
{
    using var scope = services.CreateScope();
    var sp = scope.ServiceProvider;
    var tenant = sp.GetRequiredService<TenantContext>();
    tenant.SetTenant(tenantId);

    // 1. Schema and tables (the first tenant also creates the catalog tables).
    var tableOptions = new DbContextOptionsBuilder<AppSecurityDbContext>().UseNpgsql(connectionString);
    tableOptions.UsePinotechrdSecurity(model =>
    {
        model.TenantSchemaMode = mode;
        model.ExcludeCatalogFromMigrations = !createCatalog;
    });
    await using (var tables = new AppSecurityDbContext(tableOptions.Options, sp.GetRequiredService<ISchemaProvider>()))
    {
        // SchemaName is tenant_ plus [a-z0-9_] only (TenantIdentifier), so it is safe to quote here.
        var createSchema = $"CREATE SCHEMA IF NOT EXISTS \"{tenant.SchemaName}\"";
        await tables.Database.ExecuteSqlRawAsync(createSchema);
        await tables.Database.ExecuteSqlRawAsync(tables.Database.GenerateCreateScript());
    }

    // 2. Modules and permissions (full MODULE.PERMISSION codes), a role and its first user.
    await sp.GetRequiredService<SecuritySeeder>()
        .SeedModuleAsync("Sales", "SALES", null, 1, [("View sales", "SALES.VIEW", null)]);
    var security = sp.GetRequiredService<IPinotechrdSecurityManager<AppUser, AppRole>>();
    await security.CreateRoleAsync(new AppRole { Name = "seller" });
    var role = await security.GetRoleByNameAsync("seller");
    await security.AssignPermissionsToRoleAsync(role!.Id.ToString(), ["SALES.VIEW"]);
    await security.CreateUserAsync(new AppUser { UserName = adminEmail, Email = adminEmail }, adminPassword, ["seller"]);

    // 3. Catalog rows: a plan with the module, a started subscription for this tenant id, an active tenant.
    var db = sp.GetRequiredService<AppSecurityDbContext>();
    var plan = SubscriptionPlan.Create($"Basic {tenantId}", $"BASIC_{tenantId.ToUpperInvariant()}", null, 0m);
    db.SubscriptionPlans.Add(plan);
    db.SubscriptionPlanModules.Add(SubscriptionPlanModule.Create(plan.Id, SecurityModuleId.FromCode("SALES")));
    var subscription = SystemSubscription.Create(customerName, tenantId, plan.Id, DateOnly.FromDateTime(DateTime.UtcNow));
    db.SystemSubscriptions.Add(subscription);
    var row = Tenant.Create(subscription.Id, customerName, tenantId, tenant.SchemaName!);
    row.Status = TenantStatus.Active;
    db.Tenants.Add(row);
    await db.SaveChangesAsync();
}
```

With EF Core migrations instead of `GenerateCreateScript`, run `MigrateAsync()` once per tenant in the same scope, and once with the catalog included.

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

The JWT settings are checked when the host starts, not inside `AddPinotechrdSecurity`, so tools that build the host without configuration (such as OpenAPI generation at build time) still work. A missing or weak setting makes the host fail to start with an `OptionsValidationException` that names the setting, for example `PinotechrdSecurityOptions.Jwt.Secret`. Tokens are signed with HMAC-SHA256, and only that algorithm is accepted when they are validated. The bearer handler's validation settings that the library guarantees (issuer, audience, lifetime and signing-key validation, signed tokens with an expiry, the configured issuer, audience and key, the algorithm) are applied after all your `Configure<JwtBearerOptions>` calls, even if you replace `TokenValidationParameters` entirely; your other settings are kept.

### Tenant resolution (`options.Tenancy`)

Where the tenant id comes from depends on whether the request is authenticated:

| Request | Source | Option | Default |
| --- | --- | --- | --- |
| Authenticated | Claim of the user, and nothing else | `ClaimType` | `tenant_id` |
| Anonymous | Request header | `HeaderName` | `TenantId` |

`ClaimType` is the single name used everywhere: `LoginAsync` writes the claim under it, and the middleware, the permission handler, the engine and the consistency check read it. It is exempt from the JWT bearer handler's inbound claim mapping, so a name such as `tid` (which the handler would otherwise rename to `http://schemas.microsoft.com/identity/claims/tenantid`) arrives as `tid`. Only that claim type is exempted, on the bearer scheme's own handler, in a `PostConfigure` step that later configuration cannot undo. Every other claim keeps the default mapping; for example `sub` still becomes `ClaimTypes.NameIdentifier`. `GetPrincipalFromExpiredToken` reads the claim the same way.

For an authenticated user the header is never read, so a header naming another tenant is ignored and does not cause a rejection. An authenticated user without the claim is rejected with `400 tenant_invalid`, whatever `OnMissingTenant` says: by the middleware on a path that requires a tenant, and by the consistency check before any endpoint on other paths (skip paths excepted). The JSON body and the query string are not read.

The exact rule:

1. The tenant claim is read from authenticated identities only; a claim on an unauthenticated identity is ignored. If two authenticated identities carry different tenants, the request is rejected with `tenant_invalid`.
2. If an identity is authenticated when the middleware runs, the tenant is its claim.
3. Otherwise the request may name its tenant in the header, whatever else it carries. An expired bearer token on a refresh request, or an `Authorization: Basic` header added by a gateway, does not prevent it.
4. If an endpoint then authenticates the user with its own scheme, the [tenant consistency check](#3-configure-the-middleware) requires that user's claim to equal the tenant from the header.

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
- `DbSchemaProvider` throws when no tenant is resolved, instead of falling back to the shared `identity` schema. Set `options.Tenancy.UseSharedSchemaWhenNoTenant = true` only where no tenant is expected, such as design-time tooling in `SchemaPerTenantInModel` mode; `SearchPath` mode refuses it.

### Database schemas (`UsePinotechrdSecurity`)

`PinotechrdSecurityDbContext<TUser, TRole>` keeps catalog tables (tenants, plans, subscriptions) in one constant schema and the identity and security tables in each tenant's schema. Call `UsePinotechrdSecurity()` on the context options wherever they are built, including design-time factories. There are two working setups:

| Setup | `TenantSchemaMode` | How the tenant schema is chosen |
| --- | --- | --- |
| Schema in the model (default) | `SchemaPerTenantInModel` | The tenant's schema is written into the EF Core model. `UsePinotechrdSecurity()` keys the model cache by schema, so each tenant gets its own model. Without it the context refuses to build its model, instead of reusing the first tenant's model for everyone. |
| `search_path` (PostgreSQL) | `SearchPath` | Tenant tables have no schema in the model, and the model is the same for every tenant. `UsePinotechrdSecurity()` adds interceptors that bind every connection EF Core opens to the resolved tenant's schema. |

```csharp
options.UseNpgsql(connectionString).UsePinotechrdSecurity(model =>
{
    model.TenantSchemaMode = TenantSchemaMode.SearchPath; // default: SchemaPerTenantInModel
    model.CatalogSchema = "public";                        // explicit, so catalog tables never depend on search_path
    model.ExcludeCatalogFromMigrations = true;             // tenant migrations do not create catalog tables
});
```

- The catalog table that maps plans to modules has no foreign key to a tenant table: modules live in every tenant schema and are matched by id (see `SecurityModuleId`).
- Keep these settings the same for every instance of one context type.

**`SearchPath` mode in detail.** The interceptors do the following:

- On every connection EF Core opens, they run `set_config('search_path', '<tenant schema>', false)`, read the value back, and close the connection and throw on any failure.
- The path is the tenant schema alone, without `public`, so a missing tenant table never falls back to a shared one.
- With no tenant resolved, the connection is refused. `UseSharedSchemaWhenNoTenant` is refused in this mode (the context throws when it is created), so a connection is never bound to the shared schema.
- Inside an ambient `TransactionScope`, opening is refused: a connection that enlists would set the path inside that transaction, and a rollback would restore the default path. Open the connection before entering the scope, or use `Database.BeginTransaction()`.
- Before every command EF Core sends (queries, `SaveChanges`, `ExecuteSql*`, `SqlQuery*`, migrations), the interceptors check that its connection is bound to the current tenant, on the same database session. So a command fails, instead of querying the wrong schema, when:
  - you opened the connection yourself;
  - you closed and reopened it yourself (the binding is dropped as soon as the connection reports `Closed` or `Broken`, and Npgsql's server process id is compared with the one recorded at binding);
  - the tenant changed after the connection opened.
- Each command's text is also scanned, statement by statement, the way PostgreSQL tokenises it (strings, `E''` and dollar-quoted strings, quoted identifiers, nested comments). A command is **refused before it is sent**, whether it is alone or in a batch, when a statement:
  - is `SET`, `SET SESSION`, `SET LOCAL` or `RESET` of `search_path`, `schema`, `role`, `session_authorization` or `standard_conforming_strings`; `SET ROLE`; `SET SESSION AUTHORIZATION`; `RESET ALL`; or `DISCARD ALL`;
  - is `ALTER ROLE|USER|DATABASE|SYSTEM ... SET|RESET` of those settings;
  - calls `set_config` (also schema-qualified or quoted) with a first argument that is not one plain string literal naming another setting;
  - writes to `pg_settings` (`UPDATE`, `INSERT INTO`, `DELETE FROM`, `MERGE INTO`, plain, `pg_catalog.`-qualified or quoted), which is equivalent to `SET`;
  - uses a `U&"..."` identifier.

  The bodies of `DO` blocks and `CREATE FUNCTION|PROCEDURE`, and the text of `PREPARE ... AS`, are scanned the same way. Inside a body, `EXECUTE` of exactly one string literal (optionally in parentheses) is scanned; any other `EXECUTE` (a concatenation, `format(...)`, a variable) cannot be checked and is refused, so a migration that creates such a function must run outside `SearchPath` mode. Column and table names are not matched: `UPDATE t SET search_path = @p0`, `WHERE role = @p`, `ON CONFLICT ... DO UPDATE SET role = ...`, `set_config_log`, `SELECT ... FROM pg_settings`, `current_setting('search_path')`, `SHOW search_path` and string literals all pass.
- Binding is refused when the session has `standard_conforming_strings` off (for example through `ALTER DATABASE ... SET`): the scanner reads strings as PostgreSQL does with it on, its default. This is checked in the same round trip that verifies the path.
- This is a guard against mistakes in application SQL, not a security boundary. Not checked:
  - raw ADO.NET commands on `GetDbConnection()`;
  - server-side functions or procedures already in the database that change the path when called (`SELECT public.f()`, `CALL public.p()`, inside a CTE or anywhere else), including dynamic SQL they assemble at run time.

  **A change the scanner misses persists.** The interceptors check their own record of the binding before each command; they do not re-read the real `search_path`. So if something the scanner cannot see changes the path, every later EF Core command on that connection reads the other schema until the connection closes. What closes this gap:
  - having no function or procedure in the database that calls `set_config` or `SET` on `search_path`, `role` or the session authorization, and no SQL injection;
  - for a real boundary against hostile SQL, a database role or login per tenant that can only reach its own schema.

  Re-reading the path before each command would cost a round trip per command, and checking it only at transaction boundaries would still let the commands in between run on the wrong schema, so the library does neither.
- Connection settings that break "one physical connection per open, with no default path" are refused when the connection opens; this is checked once per connection string:
  - `Multiplexing=true`;
  - `No Reset On Close=true`;
  - `Search Path`;
  - `Options` that set `search_path` in any spelling.

  A pooler between the application and PostgreSQL breaks the mode in the same way unless it pools whole sessions: PgBouncer in transaction or statement mode can run the next command on a server session bound to another tenant. Use session pooling only.

To bind connections yourself instead, set `model.ApplicationTakesResponsibilityForSearchPath = true`; you then own every case above. Your binding must refuse when there is no tenant, for example:

```csharp
var schema = tenantContext.SchemaName ?? throw new InvalidOperationException("No tenant is resolved.");
```

Without the interceptors and without that flag, the context refuses to start.

**The catalog.** Catalog tables have their own schema (`CatalogSchema`) and do not depend on `search_path`. A context used without a tenant cannot open connections in `SearchPath` mode. For catalog-only work, use a separate `DbContext` that maps only the catalog.

**Provisioning a tenant in `SearchPath` mode.** `EnsureCreated()` does not work for a second tenant: it sees that the database already has tables, returns `false` and creates nothing. Create the tenant's schema and tables yourself, with `ExcludeCatalogFromMigrations = true` so the catalog is left alone:

```csharp
tenantContext.SetTenant(newTenantId);                      // in a fresh scope
var createSchema = $"CREATE SCHEMA IF NOT EXISTS \"{tenantContext.SchemaName}\""; // tenant_<id>: only [a-z0-9_], safe to quote
await db.Database.ExecuteSqlRawAsync(createSchema);
await db.Database.ExecuteSqlRawAsync(db.Database.GenerateCreateScript()); // tables land in the tenant schema
```

With migrations, run `db.Database.MigrateAsync()` in the same way, once per tenant. Each tenant schema then gets its own `__EFMigrationsHistory`. The example above was tested on PostgreSQL 17.7: the generated script holds only the tenant tables, and a user created afterwards is visible in the new tenant only.

**`ITenantStore` and the model cache.**

- The middleware asks `ITenantStore` before the tenant is set and before any tenant-scoped context or model exists, so an unknown tenant is rejected without building a model.
- Implement `ITenantStore` against the catalog (a catalog-only context, a cache or a direct query), never through the tenant-scoped context.
- In `SchemaPerTenantInModel` mode EF Core builds one model per tenant schema and keeps a bounded number of them, measured at roughly 40 to 50. Beyond that, models are evicted and rebuilt (tens of milliseconds of CPU each), and requests that rotate through many valid tenants force rebuilds.
- Above about 40 active tenants, use `SearchPath` mode, which has one model for all tenants. The library does not offer a larger model cache.

**Pre-built and compiled models.** `UseModel(...)`, including compiled models, is not supported in `SchemaPerTenantInModel` mode: such a model holds one schema, so the context throws in its constructor. It works in `SearchPath` mode, where the model has no tenant schema.

**Membership.** The library does not check that a user belongs to a tenant. In the two setups above, the user is looked up in the tenant's own tables, so finding the user is what proves membership. In any other setup (a shared schema, a context of your own, or `ApplicationTakesResponsibilityForSearchPath` with a binding that does not hold), a user of one tenant can log in naming another tenant and get a token for it, unless you check membership in an `IIdentityValidator<TUser>`, which receives the user and the tenant id at login, two-factor completion and refresh.

**Startup membership check.** `AddPinotechrdSecurity` relies on membership only when all three hold: the context derives from `PinotechrdSecurityDbContext<TUser, TRole>`, its registered `DbContextOptions<TContext>` were built with `UsePinotechrdSecurity()`, and in `SearchPath` mode `ApplicationTakesResponsibilityForSearchPath` is off. Otherwise, unless an `IIdentityValidator<TUser>` is registered, options validation fails with an `OptionsValidationException` that names the context and the condition that failed. It fails when the host starts and also on the first read of `IOptions<PinotechrdSecurityOptions>.Value` (resolving `IPinotechrdAuthManager<TUser>`, or the JWT bearer setup), so a `ServiceCollection` built by hand, for example in tests, fails too. Register a validator that checks membership, or, if the application checks it some other way, opt out explicitly:

```csharp
services.AddPinotechrdSecurity<AppDbContext, AppUser, AppRole>(o => o.AllowUnverifiedTenantMembership = true);
```

`AllowUnverifiedTenantMembership` is one value shared by every `AddPinotechrdSecurity` call in the container, and if you bind `PinotechrdSecurityOptions` from configuration, configuration can turn the check off. The check cannot see the database provider: a provider that ignores schemas (SQLite, InMemory) on one shared database puts every tenant's users in the same tables; that setup is only safe when each tenant has its own database.

### Login and two-factor

- Tokens are issued only for the tenant the request was resolved for. `LoginAsync`, `VerifyTwoFactorCodeAsync` and `RefreshAsync` fail when no tenant is resolved or when the `tenantId` passed in differs from it. Whether the user belongs to that tenant depends on your database setup: see **Membership** under [Database schemas](#database-schemas-usepinotechrdsecurity).
- `LoginAsync` returns the same failure, `Invalid credentials`, for an unknown user, an inactive user (`IsActive` false), a wrong password, a user without a password, a locked-out account, an account Identity does not allow to sign in, and a tenant mismatch. Lockout works as in ASP.NET Core Identity.
- On every path where Identity would not hash the password against a stored hash (unknown, inactive, locked out, not allowed, no password, tenant mismatch), the password is checked against a dummy hash made once with the same hasher. This makes it harder to tell from the response time whether an account exists. It does not make the response time constant.
- When the user has two-factor enabled, `LoginAsync` returns `RequiresTwoFactor` and a `TwoFactorToken`. That answer shows the password was right, as in every two-step login. The token is opaque, protected with ASP.NET Core Data Protection, bound to the user, the tenant and the security stamp, and valid for five minutes. Pass it to `GetTwoFactorProvidersAsync`, `SendTwoFactorCodeAsync` and `VerifyTwoFactorCodeAsync`, with the same tenant as the login.
- Each token allows five code attempts, counted through `ITwoFactorAttemptStore` before the code is checked, so concurrent guesses count too. Wrong codes also count toward Identity lockout, and locked-out users are refused. When concurrent wrong codes collide on the user's concurrency stamp, the user is reloaded and the count retried (up to 10 times); a count that still cannot be recorded spends the token's remaining attempts. On a correct code the security stamp is renewed first, retried only while the stored stamp is still the token's (so two concurrent verifications of one token cannot both succeed); then the failed count is reset with the same retries, and a reset that cannot be recorded fails the verification. The default `InMemoryTwoFactorAttemptStore` keeps counts per instance: with several instances, use `AddPinotechrdEfTwoFactorAttemptStore` (below) or register a shared implementation.
- A successful verification renews the security stamp, which makes the token single use. This depends on a user store that keeps security stamps and detects concurrent updates (the EF Core store does). Renewing the stamp also invalidates pending password reset and e-mail confirmation tokens. E-mail and SMS codes depend on the stamp; authenticator-app codes do not, so with an authenticator the same code stays valid for its time window, though not with the same token.
- `SendTwoFactorCodeAsync` accepts only providers the user has, and sends a message every time it succeeds. Rate limit it in your API.
- In a deployment with several instances, Data Protection keys must be shared between them, or a token issued by one instance is rejected by another (see "Data Protection keys" below).
- `ResetPasswordAsync` answers an unknown e-mail with the same failure as an invalid reset token.

### Persistent two-factor attempt store (EF Core)

With several instances, the in-memory store lets a two-factor token try five codes on each instance. To count attempts in the database instead (opt-in):

1. Map the table in the context options, everywhere they are built (including design-time factories):

   ```csharp
   options.UseNpgsql(connectionString).UsePinotechrdSecurity(o => o.MapTwoFactorAttempts = true);
   ```

   This adds `two_factor_attempts` (`challenge_hash` primary key, the SHA-256 of the token's random challenge id; `count`, `exhausted`, `expires_at`; index on `expires_at`) in the tenant schema, never the catalog schema. With the flag off the model does not change.
2. Add a migration in your application and apply it to every tenant schema: `dotnet ef migrations add AddTwoFactorAttempts`.
3. Register the store (before or after `AddPinotechrdSecurity`): `builder.Services.AddPinotechrdEfTwoFactorAttemptStore<AppSecurityDbContext>();`

Each attempt is one atomic `UPDATE ... SET count = count + 1` (the first one inserts the row), so concurrent attempts on any instance add up to five in total; a database error refuses the attempt rather than allowing one more. The store throws inside a database transaction or `TransactionScope`, because a rollback would erase the counted attempts: call `VerifyTwoFactorCodeAsync` outside any transaction. The store shares the request's context without using its change tracker. Rows are not deleted: purge those whose `expires_at` is more than an hour old (for example `expires_at < now() - interval '1 hour'`), with a scheduled job. Deleting the row of a token that is still valid, for instance because the database clock runs ahead, would let it count from one again. If the flag is off, every call of the store throws `InvalidOperationException`.

### Data Protection keys

Two-factor tokens are protected with ASP.NET Core Data Protection. By default its keys live in a per-machine folder (or in memory), so a token issued by one instance fails on another, and after a restart of a container that does not keep the folder. Persist the keys to storage every instance shares and give the application a fixed name:

```csharp
builder.Services.AddDataProtection()
    .PersistKeysToDbContext<AppKeysDbContext>() // or PersistKeysToFileSystem, PersistKeysToStackExchangeRedis, PersistKeysToAzureBlobStorage...
    .SetApplicationName("my-app");
```

Protect the keys at rest as well (`ProtectKeysWith*`). Outside Development, `AddPinotechrdSecurity` logs a warning at startup (event id `4101`, `DataProtectionKeysNotPersisted`) when no key repository is configured. Startup continues. The check only sees whether a repository is set: it cannot tell whether that storage is shared (a local container path is not), and it also warns on Azure App Service, whose default key folder is already shared.

### Refresh tokens and sign-out

- Refresh tokens are opaque values kept through `IRefreshTokenStore`. `RefreshAsync` consumes the presented token atomically: of two concurrent refreshes with one token, exactly one succeeds.
- Tokens issued by rotating one another form a family. Presenting a token that was already used revokes the whole family (RFC 9700, section 4.14.2), so a client that sends two refreshes at once loses that session.
- A token of another tenant is refused without being consumed. The user must still exist, be active, not be locked out, be allowed to sign in, have the security stamp it had when the token was issued, and pass your `IIdentityValidator<TUser>` if you have one. Every failure returns `Invalid token`.
- `SignOutAsync` revokes all refresh tokens of the user, in every session, and renews the security stamp. Deactivating a user with `SetUserActiveStatusAsync(userId, false)` does the same.
- Access tokens already issued stay valid until they expire (`ExpiryMinutes`, 60 by default): JWT validation does not ask the server. Keep `ExpiryMinutes` short if that window matters.
- The default `InMemoryRefreshTokenStore` loses tokens on restart and does not share them between instances. It refuses a token value that is already stored. Above 10,000 entries it drops the tokens of families whose tokens have all expired, and expired revoked families. A used token is kept while its family has a live token, so replaying it is still detected; memory therefore grows with the number of refreshes per session lifetime, which is one more reason to rate limit refresh. For production use `AddPinotechrdEfRefreshTokenStore` (below), or register your own `IRefreshTokenStore` before or after `AddPinotechrdSecurity`; the default is only added when none is registered.

### Persistent refresh token store (EF Core)

For production, or more than one instance, keep refresh tokens in the database. It is opt-in; the in-memory store stays the default.

1. Map the tables in the context options, everywhere they are built (including design-time factories):

   ```csharp
   options.UseNpgsql(connectionString).UsePinotechrdSecurity(o => o.MapRefreshTokens = true);
   ```

   This adds `refresh_tokens` (`token_hash` primary key, the SHA-256 of the token; `tenant_id`, `user_id`, `family_id`, `security_stamp`, `expires_at`, `consumed_at`, `revoked_at`; indexes on `user_id` and `family_id`) and `refresh_token_families` (`family_id`, `revoked_at`) in the tenant schema, never the catalog schema. There is no foreign key to `users`. With the flag off the model does not change.
2. Add a migration in your application and apply it to every tenant schema: `dotnet ef migrations add AddRefreshTokens`.
3. Register the store (before or after `AddPinotechrdSecurity`):

   ```csharp
   builder.Services.AddPinotechrdSecurity<AppSecurityDbContext, AppUser, AppRole>(options => { /* ... */ });
   builder.Services.AddPinotechrdEfRefreshTokenStore<AppSecurityDbContext>();
   ```

The store is scoped and shares the request's context, but does not use its change tracker: it never saves your pending changes. Tokens are stored as hashes only. Consuming a token is one conditional `UPDATE`, so of concurrent refreshes with one token, on any instance, exactly one succeeds; replaying a used token revokes its family. Expiry and timestamps come from the registered `TimeProvider` (or the system clock), not the database clock, so keep the clocks of your instances synchronised. Because each tenant has its own tables, a token of another tenant is refused as not found, and `RevokeAllForUserAsync` reaches the current tenant only. If the flag is off, every call of the store throws `InvalidOperationException`.

### Writing an `IRefreshTokenStore`

- `ConsumeAsync` must be atomic: a read followed by a write lets two concurrent refreshes through.
- A revoked family stays revoked: a token saved into it later, including by a rotation that raced the revocation, must never be consumed.
- Order of the checks: unknown token is `NotFound`; another tenant is `TenantMismatch` and changes nothing; family revoked is `Revoked`; already consumed is `Reused` and revokes the family, even if the token has also expired or was revoked on its own; revoked is `Revoked`; expired is `Expired`; otherwise the token is consumed.
- Expiry is decided by the store's clock against the expiry passed to `SaveAsync`: the built-in stores use the injected `TimeProvider` and pass it as a parameter to the database. A store that uses the database clock (`now()`) instead must keep the clocks synchronised.
- Refuse a token value that already exists; never reset its state. Store a hash of the token, not the token.

A PostgreSQL consume in one statement (zero rows means not consumed; a follow-up query then classifies why and, on reuse, revokes the family):

```sql
UPDATE refresh_tokens t SET consumed_at = now()
WHERE t.token_hash = @hash AND t.tenant_id = @tenant
  AND t.consumed_at IS NULL AND t.revoked_at IS NULL AND t.expires_at > now()
  AND NOT EXISTS (SELECT 1 FROM refresh_token_families f
                  WHERE f.family_id = t.family_id AND f.revoked_at IS NOT NULL)
RETURNING t.user_id, t.tenant_id, t.family_id, t.security_stamp;
```

### For operators: what to log and alert on

- **Refresh token reuse.** When a stolen, already-used refresh token is replayed, the whole family is revoked: the attacker gets nothing, and the real user is signed out of that session and must log in again. That sign-out is the intended signal. `RefreshAsync` returns the generic `Invalid token` and the library does not log, so record it where the result is visible: in your `IRefreshTokenStore` or a decorator around it. Log every `ConsumeAsync` result of `Reused` (user id, tenant, family id, client address, user agent; never the token) and alert when it happens, more so when it repeats for one user or comes from many addresses.
- **Tenant mismatches.** `ConsumeAsync` returning `TenantMismatch`, and permission checks failing because the tenant claim differs from the resolved tenant, mean a client is sending one tenant's credentials to another. Log and alert.
- **Two-factor.** Track failed codes and lockouts per user and per client address; a spent challenge (all attempts used) is a guessing signal.
- **Login.** Track `Invalid credentials` per user and per address for credential stuffing. The library logs no tenant ids, header values or tokens; keep it that way in your own logs.

## Caching

A response cache keyed only by path and query serves one tenant's response to another, because the tenant comes from a header or a claim.

- **Output caching** (`UseOutputCache`): use `CacheOutputPerTenant()` instead of `CacheOutput()`, and place `UseOutputCache()` after `UseTenantResolution()` **and after `UseAuthorization()`**. Before authorization, a user authenticated only by an endpoint's own scheme still looks anonymous, so a per-user response could be stored under the tenant key and served to anonymous callers of that tenant. The policy refuses to cache when either middleware has not run for the request:

  ```csharp
  app.MapGet("/api/catalog", GetCatalog).CacheOutputPerTenant(policy => policy.Expire(TimeSpan.FromMinutes(5)));
  ```

  It keeps ASP.NET Core's default policy (GET and HEAD only, no authenticated requests) and adds `TenantOutputCachePolicy`. That policy varies the cache key by the resolved tenant (`TenantContext`, never the raw header). It turns caching off for the request when tenant resolution has not run (cache placed before it, or a skip path), or when a path that requires a tenant has none. For a named or base policy, add `TenantOutputCachePolicy` with `AddPolicy<TenantOutputCachePolicy>()`.
- **Response caching** (`UseResponseCaching`) and any cache in front of the application (CDN, reverse proxy, browser) are the operator's responsibility. Make tenant-specific responses uncacheable (`Cache-Control: private, no-store`), or vary them on the tenant header (`Vary: TenantId`) only if every cache in front honours `Vary`.

## Before a stable release: known limits

- **In-memory stores.** `InMemoryRefreshTokenStore` and `InMemoryTwoFactorAttemptStore` are per instance and lost on restart. With more than one instance, use `AddPinotechrdEfRefreshTokenStore` (see "Persistent refresh token store") and `AddPinotechrdEfTwoFactorAttemptStore` (see "Persistent two-factor attempt store").
- **No logging of refresh-token reuse.** The library does not log `Reused`; log it in your store (see "For operators").
- **`SearchPath` mode is PostgreSQL-only**, and needs session-level pooling (see above).
- **`SearchPath` binding is not re-checked per command.** A server-side function or procedure that changes `search_path` when called is invisible to the scanner, and the change then holds for every later command on that connection until it closes. Keep such functions out of the database, or give each tenant its own database role or login.
- **Long-lived connections.** SignalR and other long-lived connections are checked once, when they connect. Each hub method call gets a new DI scope, so `TenantContext` is empty in hub methods. Set it in every hub method (or in a hub filter) from the connection's authenticated tenant claim, after checking the claim is still valid, before touching tenant data.
- **`AuthenticateAsync` inside endpoints** is not covered by the consistency check; compare the claim with `TenantContext` yourself.
- **One database role for every tenant.** If one database role owns every tenant schema, any SQL that names a schema explicitly (`SELECT * FROM tenant_other.users`) can reach any tenant; the schema binding only governs unqualified names. For stronger isolation, use a role per tenant with grants on its own schema only, or PostgreSQL row-level security.

## Sample API

The [sample API](https://github.com/pinotechrdllc/Pinotechrd.Security/tree/develop/samples/Pinotechrd.Security.SampleApi) shows login, refresh rotation, tenant resolution and a permission check, with one demo user per tenant. From a clone of the repository:

```bash
dotnet run --project samples/Pinotechrd.Security.SampleApi/Pinotechrd.Security.SampleApi.csproj
curl -H "TenantId: tenant-a" http://localhost:5000/api/tenant
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
