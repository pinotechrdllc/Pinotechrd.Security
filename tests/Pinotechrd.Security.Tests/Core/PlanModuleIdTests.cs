using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;
using Pinotechrd.Security.Tests.Data;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>
/// A plan names its modules by id, so a module row counts for a plan only when its id is the id of its code. Codes are
/// compared normalised (trimmed, upper case) on every path, cached or not.
/// </summary>
public class PlanModuleIdTests
{
    [Theory]
    [InlineData("SALES", true)]
    [InlineData("sales", true)]
    [InlineData(" Sales ", true)]
    [InlineData("STOCK", false)]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("SA LES", false)]
    [InlineData("SALES;", false)]
    public void IsIdOf_ShouldHoldOnlyForTheIdOfTheNormalisedCode(string? code, bool expected)
    {
        SecurityModuleId.IsIdOf(SecurityModuleId.FromCode("SALES"), code).Should().Be(expected);
    }

    [Fact]
    public void IsIdOf_ShouldBeFalse_ForACodeLongerThanTheLimit_WithoutThrowing()
    {
        SecurityModuleId.IsIdOf(Guid.NewGuid(), new string('A', 101)).Should().BeFalse();
    }

    private static async Task<SecDb> PlanWithSalesAsync(Microsoft.Data.Sqlite.SqliteConnection connection, string storedCode, Guid moduleId)
    {
        var builder = new DbContextOptionsBuilder<SecDb>().UseSqlite(connection);
        builder.UsePinotechrdSecurity();
        var db = new SecDb(builder.Options, new Pinotechrd.Security.Tenancy.DbSchemaProvider(SecDbFactory.Tenant("tenant-a")));
        await db.Database.EnsureCreatedAsync();
        var plan = SubscriptionPlan.Create("Basic", "BASIC", null, null);
        // The row is written as given (id and stored code are what the test is about), so no factory is used.
        var module = new SecurityModule { Id = moduleId, Name = "Sales", Code = storedCode, IsActive = true, CreatedAt = DateTime.UtcNow };
        db.SubscriptionPlans.Add(plan);
        db.SecurityModules.Add(module);
        db.SystemSubscriptions.Add(SystemSubscription.Create("Acme", "tenant-a", plan.Id, DateOnly.FromDateTime(DateTime.UtcNow).AddDays(-1)));
        db.SubscriptionPlanModules.Add(SubscriptionPlanModule.Create(plan.Id, SecurityModuleId.FromCode("SALES")));
        await db.SaveChangesAsync();
        return db;
    }

    private static IEnumerable<ISecurityStore> Stores(SecDb db)
    {
        yield return new DbSecurityStore(db);
        yield return new TenantCacheStore(
            new DbSecurityStore(db),
            new MemoryDistributedCache(Microsoft.Extensions.Options.Options.Create(new MemoryDistributedCacheOptions())),
            Microsoft.Extensions.Options.Options.Create(new PinotechrdSecurityOptions()));
    }

    [Theory]
    [InlineData("sales")]
    [InlineData(" SALES ")]
    [InlineData("Sales")]
    public async Task AStoredCodeInAnotherCaseOrWithSpaces_ShouldCountOnEveryPath_WhenItsIdIsTheCodesId(string storedCode)
    {
        using var connection = SecDbFactory.OpenMemory();
        await using var db = await PlanWithSalesAsync(connection, storedCode, SecurityModuleId.FromCode("SALES"));

        foreach (var store in Stores(db))
        {
            (await store.IsModuleActiveAsync("tenant-a", "SALES")).Should().BeTrue(store.GetType().Name);
            (await store.IsModuleActiveAsync("tenant-a", "sales")).Should().BeTrue(store.GetType().Name);
            (await store.GetActiveModuleCodesAsync("tenant-a")).Should().Equal(["SALES"], store.GetType().Name);
            (await store.GetActiveCatalogAsync("tenant-a")).Should().ContainSingle(store.GetType().Name);
        }
    }

    [Fact]
    public async Task ARowWithThePlanModulesIdButAnotherCode_ShouldCountOnNoPath()
    {
        using var connection = SecDbFactory.OpenMemory();
        await using var db = await PlanWithSalesAsync(connection, "PREMIUM", SecurityModuleId.FromCode("SALES"));

        foreach (var store in Stores(db))
        {
            (await store.IsModuleActiveAsync("tenant-a", "PREMIUM")).Should().BeFalse(store.GetType().Name);
            (await store.IsModuleActiveAsync("tenant-a", "SALES")).Should().BeFalse(store.GetType().Name);
            (await store.GetActiveModuleCodesAsync("tenant-a")).Should().BeEmpty(store.GetType().Name);
            (await store.GetActiveCatalogAsync("tenant-a")).Should().BeEmpty(store.GetType().Name);
        }
    }

    [Fact]
    public async Task ManagerCatalog_ShouldApplyTheSameRule()
    {
        await using var rig = await SqliteSecurityManagerRig.CreateAsync();
        var plan = SubscriptionPlan.Create("Basic", "BASIC", null, null);
        rig.Db.SubscriptionPlans.Add(plan);
        rig.Db.SystemSubscriptions.Add(SystemSubscription.Create("Acme", "a", plan.Id, DateOnly.FromDateTime(DateTime.UtcNow).AddDays(-1)));
        rig.Db.SubscriptionPlanModules.Add(SubscriptionPlanModule.Create(plan.Id, SecurityModuleId.FromCode("SALES")));
        await rig.Db.SaveChangesAsync();

        (await rig.Manager.GetActiveCatalogAsync("a")).Should().ContainSingle().Which.Code.Should().Be("SALES");

        var sales = await rig.Db.SecurityModules.SingleAsync(m => m.Code == "SALES");
        sales.Code = "PREMIUM";
        await rig.Db.SaveChangesAsync();
        rig.Db.ChangeTracker.Clear();

        (await rig.Manager.GetActiveCatalogAsync("a")).Should().BeEmpty();
    }
}
