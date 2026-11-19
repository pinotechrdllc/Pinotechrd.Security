// PTRDSEC001 (SecurityModule.Create gives a random id): this fixture links its plan to that id directly.
#pragma warning disable PTRDSEC001
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;
using Xunit;

namespace Pinotechrd.Security.Tests.Hosting;

/// <summary>
/// The real wiring (AddPinotechrdSecurity, DbSecurityStore over SQLite, SecurityEngine) sees a change in the database
/// only after the tenant cache is invalidated.
/// </summary>
public class TenantCacheInvalidationIntegrationTests : IDisposable
{
    private const string Tenant = "tenant-a";

    private readonly SqliteConnection _connection = SecDbFactory.OpenMemory();
    private readonly ServiceProvider _provider;

    public TenantCacheInvalidationIntegrationTests()
    {
        var dataProvider = Substitute.For<ISecurityDataProvider>();
        dataProvider.GetCurrentUserId().Returns("user-1");
        dataProvider.GetCurrentTenantId().Returns(Tenant);
        dataProvider.GetUserPermissionsAsync("user-1").Returns(new List<string> { "SALES.VIEW" });

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddScoped<ISchemaProvider>(sp => new DbSchemaProvider(sp.GetRequiredService<TenantContext>()));
        services.AddDbContext<SecDb>(o =>
        {
            o.UseSqlite(_connection);
            o.UsePinotechrdSecurity(m =>
            {
                m.TenantSchemaMode = TenantSchemaMode.SearchPath;
                // SQLite has no search_path: the test takes responsibility instead of the interceptors.
                m.ApplicationTakesResponsibilityForSearchPath = true;
                m.CatalogSchema = null;
            });
        });
        services.AddPinotechrdSecurity<SecDb, HostUser, HostRole>(o =>
        {
            o.Jwt.Secret = TenantDatabaseApi.Secret;
            o.Jwt.Issuer = TenantDatabaseApi.Issuer;
            o.Jwt.Audience = TenantDatabaseApi.Audience;
            o.AllowUnverifiedTenantMembership = true;
        });
        services.AddSingleton(dataProvider);
        _provider = services.BuildServiceProvider();

        using var scope = NewScope();
        var db = scope.ServiceProvider.GetRequiredService<SecDb>();
        db.Database.EnsureCreated();
        var plan = SubscriptionPlan.Create("Basic", "BASIC", null, null);
        var module = SecurityModule.Create("Sales", "SALES");
        db.SubscriptionPlans.Add(plan);
        db.SecurityModules.Add(module);
        db.SystemSubscriptions.Add(new SystemSubscription
        {
            TenantName = Tenant,
            CustomerName = "Acme",
            PlanId = plan.Id,
            IsActive = true,
            StartDate = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-1))
        });
        db.SubscriptionPlanModules.Add(new SubscriptionPlanModule { PlanId = plan.Id, ModuleId = module.Id });
        db.SaveChanges();
    }

    public void Dispose()
    {
        _provider.Dispose();
        _connection.Dispose();
    }

    private IServiceScope NewScope()
    {
        var scope = _provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<TenantContext>().SetTenant(Tenant);
        return scope;
    }

    private async Task<bool> CanAccessAsync()
    {
        using var scope = NewScope();
        return await scope.ServiceProvider.GetRequiredService<ISecurityEngine>().CanAccessAsync("SALES", "VIEW");
    }

    private async Task DisableModuleAsync()
    {
        using var scope = NewScope();
        var db = scope.ServiceProvider.GetRequiredService<SecDb>();
        await db.SecurityModules.ExecuteUpdateAsync(s => s.SetProperty(m => m.IsActive, false));
    }

    private async Task CancelSubscriptionAsync()
    {
        using var scope = NewScope();
        var db = scope.ServiceProvider.GetRequiredService<SecDb>();
        await db.SystemSubscriptions.ExecuteUpdateAsync(s => s.SetProperty(x => x.IsActive, false));
    }

    private async Task InvalidateAsync()
    {
        using var scope = NewScope();
        await scope.ServiceProvider.GetRequiredService<ISecurityCacheInvalidator>().InvalidateTenantAsync(Tenant);
    }

    [Fact]
    public async Task CanAccessAsync_ShouldSeeAModuleDisabledInTheDatabase_OnlyAfterInvalidateTenantAsync()
    {
        (await CanAccessAsync()).Should().BeTrue();

        await DisableModuleAsync();
        (await CanAccessAsync()).Should().BeTrue("the cached module codes are used until the tenant is invalidated");

        await InvalidateAsync();
        (await CanAccessAsync()).Should().BeFalse();
    }

    [Fact]
    public async Task CanAccessAsync_ShouldSeeACancelledSubscription_OnlyAfterInvalidateTenantAsync()
    {
        (await CanAccessAsync()).Should().BeTrue();

        await CancelSubscriptionAsync();
        (await CanAccessAsync()).Should().BeTrue("the cached subscription state is used until the tenant is invalidated");

        await InvalidateAsync();
        (await CanAccessAsync()).Should().BeFalse();
    }
}
