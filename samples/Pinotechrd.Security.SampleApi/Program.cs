using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;
using Pinotechrd.Security.Tenancy;

// The secure baseline: PostgreSQL with one schema per tenant (SearchPath mode), an application role that is not the
// owner, the library's own tenant store and data provider, durable session stores and persisted Data Protection keys.
// Start PostgreSQL with `docker compose up -d` in this folder, then `dotnet run`. See README.md.

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

string Required(string key) => configuration[key] is { Length: > 0 } value
    ? value
    : throw new InvalidOperationException($"Configuration '{key}' is required (user secrets, environment or a secret store).");

var appConnection = Required("ConnectionStrings:Security");

// The tenant's schema is chosen per request; provisioning runs the same context as the owner (see SampleProvisioning).
builder.Services.AddScoped<ISchemaProvider, DbSchemaProvider>();
builder.Services.AddScoped<ProvisioningScope>();
builder.Services.AddDbContext<SampleSecurityDbContext>((services, options) =>
{
    var provisioning = services.GetRequiredService<ProvisioningScope>().Active;
    options.UseNpgsql(provisioning ? Required("ConnectionStrings:Owner") : appConnection);
    options.UsePinotechrdSecurity(model =>
    {
        model.TenantSchemaMode = TenantSchemaMode.SearchPath;
        model.ExcludeCatalogFromMigrations = true;
        model.MapRefreshTokens = true;
        model.MapTwoFactorAttempts = true;
    });
}, contextLifetime: ServiceLifetime.Scoped, optionsLifetime: ServiceLifetime.Scoped);

builder.Services.AddPinotechrdSecurity<SampleSecurityDbContext, SampleUser, SampleRole>(options =>
{
    // Never commit a real secret: at least 32 random bytes from a secret store.
    options.Jwt.Secret = Required("Security:JwtSecret");
    options.Jwt.Issuer = Required("Security:Issuer");
    options.Jwt.Audience = Required("Security:Audience");
    options.Tenancy.SkipPaths.Add("/health");
});

// The library's tenant store reads the catalog (active tenants only), and its default ISecurityDataProvider reads the
// user of the library token, the resolved tenant and the tenant's roles and permissions: nothing to write here.
builder.Services.AddPinotechrdCatalogTenantStore(options => options.UseNpgsql(appConnection));

// Durable, shared session state: refresh tokens and two-factor attempts in each tenant's schema, Data Protection keys
// persisted (use storage every instance shares, for example a database, Redis or blob storage, in production).
builder.Services.AddPinotechrdEfRefreshTokenStore<SampleSecurityDbContext>();
builder.Services.AddPinotechrdEfTwoFactorAttemptStore<SampleSecurityDbContext>();
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(Required("Security:KeysPath")))
    .SetApplicationName("pinotechrd-sample");

builder.Services.AddProblemDetails();
if (builder.Environment.IsDevelopment())
{
    // Development only: two-factor codes are written to the log instead of being sent.
    builder.Services.AddScoped<IPinotechrdMessageService, DevelopmentCodeLogger>();
}

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    await SampleProvisioning.EnsureProvisionedAsync(app.Services, Required("ConnectionStrings:Owner"));
}

app.UseAuthentication();
app.UseTenantResolution();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

// Anonymous: the tenant comes from the TenantId header and must exist and be active in the catalog.
app.MapPost("/api/auth/login", async (SignIn request, TenantContext tenant, IPinotechrdAuthManager<SampleUser> auth) =>
    Respond(await auth.LoginAsync(request.Email, request.Password, tenant.TenantId!)));

app.MapPost("/api/auth/2fa/send", async (TwoFactorSend request, IPinotechrdAuthManager<SampleUser> auth) =>
    (await auth.SendTwoFactorCodeAsync(request.Token, request.Provider)).Succeeded ? Results.NoContent() : Results.Unauthorized());

app.MapPost("/api/auth/2fa/verify", async (TwoFactorVerify request, TenantContext tenant, IPinotechrdAuthManager<SampleUser> auth) =>
    Respond(await auth.VerifyTwoFactorCodeAsync(request.Token, request.Provider, request.Code, tenant.TenantId!)));

app.MapPost("/api/auth/refresh", async (Refresh request, IPinotechrdAuthManager<SampleUser> auth) =>
    Respond(await auth.RefreshAsync(request.RefreshToken)));

// Ends every session of the caller: refresh tokens revoked, and access tokens refused from the next request.
app.MapPost("/api/auth/logout", [Authorize] async (IPinotechrdAuthManager<SampleUser> auth) =>
    await auth.SignOutCurrentUserAsync() ? Results.NoContent() : Results.Problem());

app.MapGet("/api/me", [Authorize] (ClaimsPrincipal user, TenantContext tenant) => Results.Ok(new
{
    tenant = tenant.TenantId,
    user = user.FindFirstValue("id"),
}));

// Permission-protected: the tenant's plan must include SALES and the user's role must grant SALES.VIEW.
app.MapGet("/api/sales", [Authorize(Policy = "SALES.VIEW")] () => Results.Ok(new { message = "Sales data" }));

app.MapGet("/api/permissions", [Authorize] async (ISecurityEngine engine) =>
    Results.Ok(await engine.GetCurrentUserPermissionsAsync()));

app.Run();

static IResult Respond(AuthResult result) =>
    result.RequiresTwoFactor ? Results.Ok(new { twoFactorToken = result.TwoFactorToken, providers = result.TwoFactorProviders })
    : result.Succeeded && result.Token != null
        ? Results.Ok(new { accessToken = result.Token.AccessToken, refreshToken = result.Token.RefreshToken, expiresAt = result.Token.ExpiresAt })
        : Results.Unauthorized();

public sealed record SignIn(string Email, string Password);
public sealed record TwoFactorSend(string Token, string Provider);
public sealed record TwoFactorVerify(string Token, string Provider, string Code);
public sealed record Refresh(string RefreshToken);

public sealed class SampleUser : BaseSecurityUser;

public sealed class SampleRole : BaseSecurityRole;

public sealed class SampleSecurityDbContext(DbContextOptions<SampleSecurityDbContext> options, ISchemaProvider schemaProvider)
    : PinotechrdSecurityDbContext<SampleUser, SampleRole>(options, schemaProvider);

/// <summary>Marks a scope that provisions, so the context connects as the owner instead of the application role.</summary>
public sealed class ProvisioningScope
{
    public bool Active { get; set; }
}

/// <summary>Development only: writes two-factor codes to the log. Use a real email or SMS sender elsewhere.</summary>
public sealed class DevelopmentCodeLogger(ILogger<DevelopmentCodeLogger> logger) : IPinotechrdMessageService
{
    public Task SendCodeAsync(string destination, string code, SecurityCodeType codeType, CancellationToken cancellationToken = default)
    {
        logger.LogWarning("Development two-factor code for {Destination}: {Code}", destination, code);
        return Task.CompletedTask;
    }
}
