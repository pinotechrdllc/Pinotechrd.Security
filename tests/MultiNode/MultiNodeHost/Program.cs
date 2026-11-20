// Validation host for Pinotechrd.Security across several nodes. Synthetic data, local containers only.
//
//   dotnet run -- provision   creates the catalog, two tenants (acme, globex), their users and the grants, as the
//                             deployment pipeline would, with the owner role.
//   dotnet run                serves one node. Run two of them with different NODE_NAME and URLS.
//
// Each node: tenant data through PgBouncer with that tenant's own database role, Redis as IDistributedCache, Data
// Protection keys in a shared folder, EF Core stores for refresh tokens and two-factor attempts, Production environment.
// The /admin and /test endpoints exist only for the validation and are not protected: never copy them.

using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Npgsql;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;
using Pinotechrd.Security.Tenancy;

var provisioning = args.Contains("provision");
var settings = Settings.FromEnvironment();

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args.Where(a => a != "provision").ToArray(),
    EnvironmentName = provisioning ? Environments.Development : Environments.Production,
});
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.Logging.AddFilter(SecurityEvents.Category, LogLevel.Information);

builder.Services.AddScoped<ISchemaProvider, DbSchemaProvider>();
builder.Services.AddDbContext<AppDb>((sp, options) =>
{
    var tenant = sp.GetRequiredService<TenantContext>().TenantId
        ?? throw new InvalidOperationException("No tenant is resolved.");
    // Provisioning runs as the owner, directly; a node runs as the tenant's own role, through the pooler.
    options.UseNpgsql(provisioning ? settings.OwnerConnection : settings.TenantConnection(tenant));
    options.UsePinotechrdSecurity(m =>
    {
        m.TenantSchemaMode = settings.Mode;
        m.ExcludeCatalogFromMigrations = true;
        m.MapRefreshTokens = true;
        m.MapTwoFactorAttempts = true;
        m.ConnectionPoolerUsesSessionMode = !provisioning;
    });
}, contextLifetime: ServiceLifetime.Scoped, optionsLifetime: ServiceLifetime.Scoped);

builder.Services.AddStackExchangeRedisCache(o => o.Configuration = settings.Redis);
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(settings.KeysDirectory))
    .SetApplicationName("pinotechrd-multinode");

builder.Services.AddPinotechrdSecurity<AppDb, AppUser, AppRole>(o =>
{
    o.Jwt.Secret = settings.JwtSecret;
    o.Jwt.Issuer = "pinotechrd-multinode";
    o.Jwt.Audience = "pinotechrd-multinode-clients";
    o.Tenancy.SkipPaths.Add("/health");
    o.Tenancy.SkipPaths.Add("/test/code");
});
builder.Services.AddPinotechrdEfRefreshTokenStore<AppDb>();
builder.Services.AddPinotechrdEfTwoFactorAttemptStore<AppDb>();

builder.Services.AddProblemDetails();
builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton(settings);
// The library's defaults: the catalog-backed tenant store on the read-only catalog role, and (registered by
// AddPinotechrdSecurity) the data provider.
builder.Services.AddPinotechrdCatalogTenantStore(o => o.UseNpgsql(settings.CatalogConnection));
builder.Services.AddScoped<IPinotechrdMessageService, RedisCodeSink>();

var app = builder.Build();

if (provisioning)
{
    await Provisioning.RunAsync(app.Services, settings);
    return;
}

app.UseAuthentication();
app.UseTenantResolution();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { node = settings.NodeName, mode = settings.Mode.ToString() }));

app.MapPost("/api/auth/login", async (Credentials body, TenantContext tenant, IPinotechrdAuthManager<AppUser> auth) =>
    Respond(await auth.LoginAsync(body.Email, body.Password, tenant.TenantId!)));

app.MapPost("/api/auth/2fa/send", async (TwoFactorSend body, IPinotechrdAuthManager<AppUser> auth) =>
    (await auth.SendTwoFactorCodeAsync(body.Token, body.Provider)).Succeeded ? Results.NoContent() : Results.Unauthorized());

app.MapPost("/api/auth/2fa/verify", async (TwoFactorVerify body, TenantContext tenant, IPinotechrdAuthManager<AppUser> auth) =>
    Respond(await auth.VerifyTwoFactorCodeAsync(body.Token, body.Provider, body.Code, tenant.TenantId!)));

app.MapPost("/api/auth/refresh", async (RefreshBody body, IPinotechrdAuthManager<AppUser> auth) =>
    Respond(await auth.RefreshAsync(body.RefreshToken)));

app.MapPost("/api/auth/logout", [Authorize] async (IPinotechrdAuthManager<AppUser> auth) =>
    await auth.SignOutCurrentUserAsync() ? Results.NoContent() : Results.Problem());

app.MapGet("/api/me", [Authorize] (ClaimsPrincipal user, TenantContext tenant) =>
    Results.Ok(new { node = settings.NodeName, tenant = tenant.TenantId, user = user.FindFirstValue("id") }));

app.MapGet("/api/sales", [Authorize(Policy = "SALES.VIEW")] () => Results.Ok(new { node = settings.NodeName }));

// ---- Validation-only endpoints ----------------------------------------------------------------------------------

// Ends every session of a user, as an administrator would.
app.MapPost("/admin/revoke", async (EmailBody body, UserManager<AppUser> users, IPinotechrdSecurityManager<AppUser, AppRole> manager) =>
{
    var user = await users.FindByEmailAsync(body.Email);
    return user != null && await manager.RevokeUserSessionsAsync(user.Id.ToString()) ? Results.NoContent() : Results.NotFound();
});

// Removes or restores the SALES module in the tenant's plan, with the owner (the tenant roles only read the catalog),
// then optionally invalidates the tenant's cached subscription data.
app.MapPost("/admin/plan", async (PlanChange body, TenantContext tenant, ISecurityCacheInvalidator invalidator) =>
{
    await using var connection = new NpgsqlConnection(settings.OwnerConnection);
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = body.Include
        ? """
          INSERT INTO public.subscription_plan_modules ("Id", "PlanId", "ModuleId", "CreatedAt")
          SELECT gen_random_uuid(), s."PlanId", @module, now() FROM public.system_subscriptions s
          WHERE s."TenantName" = @tenant AND NOT EXISTS (
            SELECT 1 FROM public.subscription_plan_modules m WHERE m."PlanId" = s."PlanId" AND m."ModuleId" = @module)
          """
        : """
          DELETE FROM public.subscription_plan_modules m USING public.system_subscriptions s
          WHERE m."PlanId" = s."PlanId" AND s."TenantName" = @tenant AND m."ModuleId" = @module
          """;
    command.Parameters.AddWithValue("tenant", tenant.TenantId!);
    command.Parameters.AddWithValue("module", SecurityModuleId.FromCode("SALES"));
    var rows = await command.ExecuteNonQueryAsync();
    if (body.Invalidate) await invalidator.InvalidateTenantAsync(tenant.TenantId!);
    return Results.Ok(new { rows });
});

// Raw SQL on the request's own connection that names another tenant's schema: only the database role can stop it.
app.MapGet("/test/cross-tenant", async (string target, AppDb db) =>
{
    // EF opens and binds the connection; the command below is raw ADO.NET on it, which the interceptors do not see.
    await db.Database.OpenConnectionAsync();
    var connection = db.Database.GetDbConnection();
    try
    {
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT count(*) FROM \"{TenantIdentifier.ToSchemaName(target)}\".users";
        return Results.Ok(new { read = true, count = Convert.ToInt64(await command.ExecuteScalarAsync()) });
    }
    catch (PostgresException e)
    {
        return Results.Ok(new { read = false, sqlState = e.SqlState });
    }
    finally
    {
        await db.Database.CloseConnectionAsync();
    }
});

// The last two-factor code "sent" to an address (the message service writes it to Redis).
app.MapGet("/test/code", async (string destination, IDistributedCache cache) =>
    await cache.GetStringAsync(RedisCodeSink.Key(destination)) is { } code ? Results.Ok(new { code }) : Results.NotFound());

app.Run();

static IResult Respond(AuthResult result) =>
    result.RequiresTwoFactor ? Results.Ok(new { twoFactorToken = result.TwoFactorToken })
    : result.Succeeded && result.Token != null
        ? Results.Ok(new { access = result.Token.AccessToken, refresh = result.Token.RefreshToken })
        : Results.Unauthorized();

public sealed record Credentials(string Email, string Password);
public sealed record TwoFactorSend(string Token, string Provider);
public sealed record TwoFactorVerify(string Token, string Provider, string Code);
public sealed record RefreshBody(string RefreshToken);
public sealed record EmailBody(string Email);
public sealed record PlanChange(bool Include, bool Invalidate);

public sealed class AppUser : BaseSecurityUser;

public sealed class AppRole : BaseSecurityRole;

public sealed class AppDb(DbContextOptions<AppDb> options, ISchemaProvider schemaProvider)
    : PinotechrdSecurityDbContext<AppUser, AppRole>(options, schemaProvider);

public sealed class Settings
{
    public required string NodeName { get; init; }
    public required TenantSchemaMode Mode { get; init; }
    public required string OwnerConnection { get; init; }
    public required string PoolerHostPort { get; init; }
    public required string Redis { get; init; }
    public required string KeysDirectory { get; init; }
    public required string JwtSecret { get; init; }

    public static readonly string[] Tenants = ["acme", "globex"];

    public static string RoleOf(string tenant) => "tenant_" + tenant + "_app";

    public string TenantConnection(string tenant)
    {
        if (!Tenants.Contains(tenant)) throw new InvalidOperationException("Unknown tenant.");
        return $"{PoolerHostPort};Database=sec;Username={RoleOf(tenant)};Password=app-{tenant}-pass;Maximum Pool Size=10";
    }

    public string CatalogConnection => $"{PoolerHostPort};Database=sec;Username=catalog_app;Password=catalog-pass;Maximum Pool Size=5";

    public static Settings FromEnvironment()
    {
        string Env(string name, string fallback) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } v ? v : fallback;
        return new Settings
        {
            NodeName = Env("NODE_NAME", "node"),
            Mode = Enum.Parse<TenantSchemaMode>(Env("SCHEMA_MODE", nameof(TenantSchemaMode.SearchPath))),
            OwnerConnection = Env("PG_OWNER", "Host=localhost;Port=57432;Database=sec;Username=sec_owner;Password=owner-pass"),
            PoolerHostPort = Env("PG_POOLER", "Host=localhost;Port=57433"),
            Redis = Env("REDIS", "localhost:57379"),
            KeysDirectory = Env("KEYS_DIR", Path.Combine(Path.GetTempPath(), "pinotechrd-multinode-keys")),
            // A random secret generated once per run by run.ps1 and given to every node.
            JwtSecret = Env("JWT_SECRET", ""),
        };
    }
}

/// <summary>"Sends" a two-factor code by writing it to Redis, where the validation reads it from any node.</summary>
public sealed class RedisCodeSink(IDistributedCache cache) : IPinotechrdMessageService
{
    public static string Key(string destination) => "multinode:code:" + destination;

    public Task SendCodeAsync(string destination, string code, SecurityCodeType codeType, CancellationToken cancellationToken = default) =>
        cache.SetStringAsync(Key(destination), code, new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5) }, cancellationToken);
}
