using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Pinotechrd.Security.Entities;
using NSubstitute;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Tests.Hosting;

/// <summary>
/// A real <see cref="WebApplication"/> listening on a loopback port chosen by the OS, so tests can exercise the
/// actual middleware pipeline and the real JWT bearer handler without a TestServer package.
/// </summary>
internal sealed class InProcessHost : IAsyncDisposable
{
    private readonly WebApplication _app;

    private InProcessHost(WebApplication app, HttpClient client)
    {
        _app = app;
        Client = client;
    }

    public HttpClient Client { get; }

    public IServiceProvider Services => _app.Services;

    public static async Task<InProcessHost> StartAsync(
        Action<WebApplicationBuilder> configureServices,
        Action<WebApplication> configurePipeline)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Production });
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        configureServices(builder);

        var app = builder.Build();
        configurePipeline(app);
        await app.StartAsync();

        var address = app.Urls.First();
        return new InProcessHost(app, new HttpClient { BaseAddress = new Uri(address) });
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}

public sealed class HostUser : BaseSecurityUser;

public sealed class HostRole : BaseSecurityRole;

/// <summary>Identity context over the EF Core in-memory provider that satisfies <see cref="ISecurityDbContext"/>.</summary>
public sealed class HostSecurityDbContext : IdentityDbContext<HostUser, HostRole, Guid>, ISecurityDbContext
{
    public HostSecurityDbContext(DbContextOptions<HostSecurityDbContext> options) : base(options)
    {
    }

    public IQueryable<SecurityPermission> Permissions => Array.Empty<SecurityPermission>().AsQueryable();
    public IQueryable<SecurityModule> Modules => Array.Empty<SecurityModule>().AsQueryable();
    public IQueryable<SystemSubscription> SystemSubscriptions => Array.Empty<SystemSubscription>().AsQueryable();
    public IQueryable<RolePermission> RolePermissions => Array.Empty<RolePermission>().AsQueryable();
    public IQueryable<UserModulePermission> UserModulePermissions => Array.Empty<UserModulePermission>().AsQueryable();
    public IQueryable<SubscriptionPlanModule> SubscriptionPlanModules => Array.Empty<SubscriptionPlanModule>().AsQueryable();
}

/// <summary>Tenant store that knows a fixed set of tenants and records every id it was asked about.</summary>
public sealed class FixedTenantStore : ITenantStore
{
    private readonly HashSet<string> _tenants;

    public FixedTenantStore(params string[] tenants) => _tenants = new HashSet<string>(tenants, StringComparer.Ordinal);

    public System.Collections.Concurrent.ConcurrentQueue<string> Asked { get; } = new();

    public Task<bool> TenantExistsAsync(string tenantId, CancellationToken cancellationToken = default)
    {
        Asked.Enqueue(tenantId);
        return Task.FromResult(_tenants.Contains(tenantId));
    }
}

internal static class HostStubs
{
    /// <summary>
    /// Registers what the host application owns: the tenant store, the security data provider, and a security engine
    /// that returns a fixed permission list. Call it after AddPinotechrdSecurity so it replaces the defaults.
    /// </summary>
    public static IServiceCollection AddHostStubs(this IServiceCollection services, FixedTenantStore? tenants = null)
    {
        services.AddSingleton<ITenantStore>(tenants ?? new FixedTenantStore("tenant-a", "tenant-b"));
        // The current user is the authenticated request's "id" claim, as an application's provider would read it.
        services.AddHttpContextAccessor();
        services.AddSingleton(sp =>
        {
            var http = sp.GetRequiredService<Microsoft.AspNetCore.Http.IHttpContextAccessor>();
            var provider = Substitute.For<ISecurityDataProvider>();
            provider.GetCurrentUserId().Returns(_ => http.HttpContext?.User.FindFirst("id")?.Value);
            return provider;
        });
        var engine = Substitute.For<ISecurityEngine>();
        engine.GetPermissionsAsync(Arg.Any<string>()).Returns(new[] { "permissions.read" });
        services.AddScoped(_ => engine);
        return services;
    }
}
