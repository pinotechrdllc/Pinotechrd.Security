using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// A plan in the shared catalog names its modules by id. A module row in a tenant schema counts for the plan only when its
/// code belongs to its id: changing the code of a plan-mapped row must not make the plan include the new code.
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresModuleEntitlementTests(PostgresFixture postgres)
{
    public static IEnumerable<object[]> Modes() => PgProvisioning.BothModes();

    private static async Task SeedAsync(string cs, TenantSchemaMode mode)
    {
        await PgProvisioning.ProvisionAsync(cs, mode, "a", "b");
        await using (var catalog = PgProvisioning.NewContext(cs, mode, "a"))
        {
            var plan = SubscriptionPlan.Create("Basic", "BASIC", null, null);
            catalog.SubscriptionPlans.Add(plan);
            catalog.SubscriptionPlanModules.Add(SubscriptionPlanModule.Create(plan.Id, SecurityModuleId.FromCode("SALES")));
            foreach (var tenant in new[] { "a", "b" })
            {
                catalog.SystemSubscriptions.Add(SystemSubscription.Create("Customer " + tenant, tenant, plan.Id, DateOnly.FromDateTime(DateTime.UtcNow).AddDays(-1)));
            }

            await catalog.SaveChangesAsync();
        }

        foreach (var tenant in new[] { "a", "b" })
        {
            await using var db = PgProvisioning.NewContext(cs, mode, tenant);
            var seeder = new SecuritySeeder(db);
            await seeder.SeedModuleAsync("Sales", "SALES", null, 1, [("View", "SALES.VIEW", null)]);
            await seeder.SeedModuleAsync("Premium", "PREMIUM", null, 2, [("View", "PREMIUM.VIEW", null)]);
            await db.SaveChangesAsync();
        }
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ChangingTheCodeOfAPlanMappedModule_ShouldNotGrantTheNewCode(TenantSchemaMode mode)
    {
        var cs = await postgres.CreateDatabaseAsync();
        await SeedAsync(cs, mode);

        await using (var a = PgProvisioning.NewContext(cs, mode, "a"))
        {
            a.SecurityModules.Remove(await a.SecurityModules.SingleAsync(m => m.Code == "PREMIUM"));
            await a.SaveChangesAsync();
            (await a.SecurityModules.SingleAsync(m => m.Code == "SALES")).Code = "PREMIUM";
            await a.SaveChangesAsync();
        }

        await using (var a = PgProvisioning.NewContext(cs, mode, "a"))
        {
            var store = new DbSecurityStore(a);
            (await store.IsModuleActiveAsync("a", "PREMIUM")).Should().BeFalse("the plan names SALES by id, not PREMIUM");
            (await store.IsModuleActiveAsync("a", "SALES")).Should().BeFalse("the row with SALES's id no longer has SALES's code");
            (await store.GetActiveModuleCodesAsync("a")).Should().BeEmpty();
            (await store.GetActiveCatalogAsync("a")).Should().BeEmpty();
        }

        await using (var b = PgProvisioning.NewContext(cs, mode, "b"))
        {
            var store = new DbSecurityStore(b);
            (await store.IsModuleActiveAsync("b", "SALES")).Should().BeTrue("tenant b's rows were not changed");
            (await store.IsModuleActiveAsync("b", "PREMIUM")).Should().BeFalse();
            (await store.GetActiveModuleCodesAsync("b")).Should().Equal("SALES");
        }
    }
}
