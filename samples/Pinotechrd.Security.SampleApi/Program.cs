using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Models;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// One in-memory database per tenant stands in for one schema per tenant (the in-memory provider has no schemas).
// UsePinotechrdSecurity() keys the EF Core model by tenant schema; with a relational database it is what keeps
// each tenant's users in its own schema.
builder.Services.AddScoped<ISchemaProvider, DbSchemaProvider>();
builder.Services.AddDbContext<SampleSecurityDbContext>((services, options) =>
{
    var tenant = services.GetRequiredService<TenantContext>().TenantId
        ?? throw new InvalidOperationException("No tenant is resolved for this request.");
    options.UseInMemoryDatabase("pinotechrd-security-sample-" + tenant).UsePinotechrdSecurity();
});

builder.Services.AddPinotechrdSecurity<SampleSecurityDbContext, SampleUser, SampleRole>(options =>
{
    options.Jwt.Secret = "sample-dev-secret-minimum-length-32";
    options.Jwt.Issuer = "Pinotechrd.Sample";
    options.Jwt.Audience = "Pinotechrd.Sample.Client";

    options.Tenancy.SkipPaths.Add("/health");
});

builder.Services.AddScoped<ITenantStore, InMemoryTenantStore>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ISecurityDataProvider, SampleSecurityDataProvider>();
builder.Services.AddScoped<ISecurityStore, SampleSecurityStore>();

var app = builder.Build();

// One demo user per tenant. Each lives only in its tenant's database.
foreach (var (tenant, email) in new[] { ("tenant-a", "alice@tenant-a.test"), ("tenant-b", "bob@tenant-b.test") })
{
    using var scope = app.Services.CreateScope();
    scope.ServiceProvider.GetRequiredService<TenantContext>().SetTenant(tenant);
    var users = scope.ServiceProvider.GetRequiredService<UserManager<SampleUser>>();
    await users.CreateAsync(new SampleUser { UserName = email, Email = email }, SampleCredentials.Password);
}

app.UseAuthentication();
app.UseTenantResolution();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new
{
    Status = "ok",
    Message = "Sample API is running"
}));

// Anonymous: the tenant comes from the TenantId header (an expired bearer token or a gateway Authorization header does not change that).
app.MapPost("/api/auth/login", async (
    SampleLoginRequest request,
    TenantContext tenantContext,
    IPinotechrdAuthManager<SampleUser> auth) =>
{
    var result = await auth.LoginAsync(request.Email, request.Password, tenantContext.TenantId!);
    return ToResponse(result);
});

// Anonymous: the tenant comes from the TenantId header, never from the token itself.
app.MapPost("/api/auth/refresh", async (
    SampleRefreshRequest request,
    IPinotechrdAuthManager<SampleUser> auth) =>
{
    var result = await auth.RefreshAsync(request.RefreshToken);
    return ToResponse(result);
});

app.MapGet("/api/secure", [Authorize] () => Results.Ok(new
{
    Message = "Authorized endpoint from Pinotechrd.Security sample"
}));

// Permission check: the tenant claim must match the resolved tenant, then the engine checks SAMPLE.READ.
app.MapGet("/api/reports", [Authorize(Policy = "Sample.Read")] () => Results.Ok(new
{
    Message = "Permission-protected endpoint"
}));

app.MapGet("/api/tenant", (TenantContext tenantContext) => Results.Ok(new
{
    TenantId = tenantContext.TenantId,
    Schema = tenantContext.SchemaName
}));

app.Run();

static IResult ToResponse(AuthResult result) => result.Succeeded && result.Token != null
    ? Results.Ok(new
    {
        result.Token.AccessToken,
        result.Token.RefreshToken,
        result.Token.ExpiresAt
    })
    : Results.Unauthorized();

public static class SampleCredentials
{
    // Demo only. Never ship fixed credentials.
    public const string Password = "Sample-Passw0rd";
}

public sealed class SampleUser : BaseSecurityUser
{
}

public sealed class SampleRole : BaseSecurityRole
{
}

public sealed class SampleSecurityDbContext : PinotechrdSecurityDbContext<SampleUser, SampleRole>
{
    public SampleSecurityDbContext(DbContextOptions<SampleSecurityDbContext> options, ISchemaProvider schemaProvider)
        : base(options, schemaProvider)
    {
    }
}

public sealed class InMemoryTenantStore : ITenantStore
{
    // Case-exact: tenant ids are compared as stored, never folded.
    private static readonly HashSet<string> ValidTenantIds = new(StringComparer.Ordinal)
    {
        "demo",
        "tenant-a",
        "tenant-b"
    };

    public Task<bool> TenantExistsAsync(string tenantId)
    {
        return Task.FromResult(ValidTenantIds.Contains(tenantId));
    }
}

public sealed record SampleLoginRequest(string Email, string Password);
public sealed record SampleRefreshRequest(string RefreshToken);

public sealed class SampleSecurityDataProvider : ISecurityDataProvider
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly TenantContext _tenantContext;

    public SampleSecurityDataProvider(IHttpContextAccessor httpContextAccessor, TenantContext tenantContext)
    {
        _httpContextAccessor = httpContextAccessor;
        _tenantContext = tenantContext;
    }

    public string? GetCurrentUserId()
    {
        // Tokens issued by IPinotechrdAuthManager carry the user id in the "id" claim.
        return _httpContextAccessor.HttpContext?.User.FindFirstValue("id");
    }

    // The tenant whose data this provider reads. The engine compares it with the signed-in user's tenant claim
    // (or, for anonymous requests and background work, with TenantContext) and denies on any difference.
    public string? GetCurrentTenantId() => _tenantContext.TenantId;

    public Task<IEnumerable<string>> GetUserRolesAsync(string userId)
        => Task.FromResult<IEnumerable<string>>(["sample-role"]);

    public Task<IEnumerable<string>> GetUserPermissionsAsync(string userId)
        => Task.FromResult<IEnumerable<string>>(["sample.read", "sample.write"]);
}

public sealed class SampleSecurityStore : ISecurityStore
{
    public Task<bool> IsSubscriptionActiveAsync(string tenantId) => Task.FromResult(true);

    public Task<bool> IsModuleActiveAsync(string tenantId, string moduleCode) => Task.FromResult(true);

    public Task<IEnumerable<string>> GetActiveModuleCodesAsync(string tenantId)
        => Task.FromResult<IEnumerable<string>>(["CORE", "SAMPLE"]);

    public Task<IReadOnlyList<SecurityModule>> GetActiveCatalogAsync(string tenantId)
        => Task.FromResult<IReadOnlyList<SecurityModule>>([]);

    public Task<IReadOnlyList<UserPermissionOverride>> GetUserOverridesAsync(string userId)
        => Task.FromResult<IReadOnlyList<UserPermissionOverride>>([]);
}
