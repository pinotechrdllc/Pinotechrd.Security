using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Pinotechrd.Security.Options;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Models;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<SampleSecurityDbContext>(options =>
    options.UseInMemoryDatabase("pinotechrd-security-sample"));

builder.Services.AddPinotechrdSecurity<SampleSecurityDbContext, SampleUser, SampleRole>(options =>
{
    options.Jwt.Secret = "sample-dev-secret-minimum-length-32";
    options.Jwt.Issuer = "Pinotechrd.Sample";
    options.Jwt.Audience = "Pinotechrd.Sample.Client";

    options.Tenancy.SkipPaths.Add("/health");
    options.Tenancy.SkipPaths.Add("/api/auth/token");
});

builder.Services.AddScoped<ITenantStore, InMemoryTenantStore>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ISecurityDataProvider, SampleSecurityDataProvider>();
builder.Services.AddScoped<ISecurityStore, SampleSecurityStore>();

var app = builder.Build();

app.UseAuthentication();
app.UseTenantResolution();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new
{
    Status = "ok",
    Message = "Sample API is running"
}));

app.MapPost("/api/auth/token", async (
    SampleTokenRequest request,
    ITokenProvider tokenProvider,
    IRefreshTokenStore refreshTokenStore,
    ITenantStore tenantStore,
    IOptions<PinotechrdSecurityOptions> securityOptions) =>
{
    if (!await tenantStore.TenantExistsAsync(request.TenantId))
    {
        return Results.BadRequest(new { Message = "Invalid tenant." });
    }

    var options = securityOptions.Value;
    var accessClaims = new List<Claim>
    {
        new(ClaimTypes.NameIdentifier, request.UserId),
        new("sub", request.UserId),
        new(options.Tenancy.ClaimType, request.TenantId)
    };

    var accessToken = tokenProvider.GenerateAccessToken(accessClaims);
    var refreshToken = tokenProvider.GenerateRefreshToken();
    var expiresAtUtc = DateTime.UtcNow.AddDays(options.Jwt.RefreshTokenExpiryDays);

    await refreshTokenStore.SaveAsync(request.UserId, request.TenantId, refreshToken, expiresAtUtc);

    return Results.Ok(new
    {
        AccessToken = accessToken,
        RefreshToken = refreshToken,
        ExpiresAtUtc = expiresAtUtc
    });
});

app.MapPost("/api/auth/refresh", async (
    SampleRefreshRequest request,
    TenantContext tenantContext,
    ITokenProvider tokenProvider,
    IRefreshTokenStore refreshTokenStore,
    IOptions<PinotechrdSecurityOptions> securityOptions) =>
{
    // The tenant comes from the request (TenantId header), never from the token itself.
    // Atomic: of two concurrent refreshes with one token only one succeeds, and reuse revokes the family.
    var validation = await refreshTokenStore.ConsumeAsync(request.RefreshToken, tenantContext.TenantId!);
    if (!validation.Succeeded || string.IsNullOrWhiteSpace(validation.UserId) || string.IsNullOrWhiteSpace(validation.TenantId))
    {
        return Results.Unauthorized();
    }

    var options = securityOptions.Value;
    var refreshedClaims = new List<Claim>
    {
        new(ClaimTypes.NameIdentifier, validation.UserId),
        new("sub", validation.UserId),
        new(options.Tenancy.ClaimType, validation.TenantId)
    };

    var accessToken = tokenProvider.GenerateAccessToken(refreshedClaims);
    var refreshToken = tokenProvider.GenerateRefreshToken();
    var expiresAtUtc = DateTime.UtcNow.AddDays(options.Jwt.RefreshTokenExpiryDays);

    await refreshTokenStore.SaveAsync(validation.UserId, validation.TenantId, refreshToken, expiresAtUtc, validation.FamilyId);

    return Results.Ok(new
    {
        AccessToken = accessToken,
        RefreshToken = refreshToken,
        ExpiresAtUtc = expiresAtUtc
    });
});

app.MapGet("/api/secure", [Authorize] () => Results.Ok(new
{
    Message = "Authorized endpoint from Pinotechrd.Security sample"
}));

app.MapGet("/api/tenant", (TenantContext tenantContext) => Results.Ok(new
{
    TenantId = tenantContext.TenantId,
    Schema = tenantContext.SchemaName
}));

app.Run();

public sealed class SampleUser : BaseSecurityUser
{
}

public sealed class SampleRole : BaseSecurityRole
{
}

public sealed class SampleSecurityDbContext : IdentityDbContext<SampleUser, SampleRole, Guid>, ISecurityDbContext
{
    public SampleSecurityDbContext(DbContextOptions<SampleSecurityDbContext> options)
        : base(options)
    {
    }

    public DbSet<SecurityPermission> SecurityPermissions { get; set; } = null!;
    public DbSet<SecurityModule> SecurityModules { get; set; } = null!;
    public DbSet<SystemSubscription> SecuritySubscriptions { get; set; } = null!;
    public DbSet<RolePermission> SecurityRolePermissions { get; set; } = null!;
    public DbSet<UserModulePermission> SecurityUserPermissions { get; set; } = null!;
    public DbSet<SubscriptionPlanModule> SecurityPlanModules { get; set; } = null!;

    IQueryable<SecurityPermission> ISecurityDbContext.Permissions => SecurityPermissions;
    IQueryable<SecurityModule> ISecurityDbContext.Modules => SecurityModules;
    IQueryable<SystemSubscription> ISecurityDbContext.SystemSubscriptions => SecuritySubscriptions;
    IQueryable<RolePermission> ISecurityDbContext.RolePermissions => SecurityRolePermissions;
    IQueryable<UserModulePermission> ISecurityDbContext.UserModulePermissions => SecurityUserPermissions;
    IQueryable<SubscriptionPlanModule> ISecurityDbContext.SubscriptionPlanModules => SecurityPlanModules;
}

public sealed class InMemoryTenantStore : ITenantStore
{
    private static readonly HashSet<string> ValidTenantIds = new(StringComparer.OrdinalIgnoreCase)
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

public sealed record SampleTokenRequest(string UserId, string TenantId);
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
        return _httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? _httpContextAccessor.HttpContext?.User.FindFirstValue("sub");
    }

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
