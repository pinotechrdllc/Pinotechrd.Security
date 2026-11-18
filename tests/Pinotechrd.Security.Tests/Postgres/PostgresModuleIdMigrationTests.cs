using System.Text.RegularExpressions;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Tests.Data;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// The module-id migration script of the CHANGELOG, read from the CHANGELOG at test time, applied to a database whose two tenants
/// were seeded with random module ids (what a database seeded by an earlier version looks like).
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresModuleIdMigrationTests(PostgresFixture postgres)
{
    public static IEnumerable<object[]> Modes() => PgProvisioning.BothModes();

    private static string MigrationSql()
    {
        var changelog = File.ReadAllText(SessionChangeDetectorTests.RepoFile("CHANGELOG.md"));
        var blocks = Regex.Matches(changelog, "```sql\\s*\\n(?<sql>.*?)```", RegexOptions.Singleline)
            .Select(m => m.Groups["sql"].Value)
            .Where(sql => sql.Contains("pinotechrd_module_id_map", StringComparison.Ordinal))
            .ToList();
        blocks.Should().ContainSingle("the CHANGELOG holds exactly one module-id migration script");
        return blocks[0].Replace("{{SCHEMAS}}", "ARRAY['tenant_a','tenant_b']", StringComparison.Ordinal);
    }

    private static async Task<List<(string Code, Guid Id)>> ModulesAsync(string cs, TenantSchemaMode mode, string tenant)
    {
        await using var db = PgProvisioning.NewContext(cs, mode, tenant);
        return (await db.SecurityModules.AsNoTracking().OrderBy(m => m.Code).ToListAsync()).Select(m => (m.Code, m.Id)).ToList();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task MigrationScript_ShouldAlignRandomModuleIdsWithFromCode_AndRepointPermissionsAndPlans(TenantSchemaMode mode)
    {
        var cs = await postgres.CreateDatabaseAsync();
        await PgProvisioning.ProvisionAsync(cs, mode, "a", "b");

        // Seed with random ids, the way a database from before deterministic ids looks. Plans refer to tenant a's random ids.
        var planId = Guid.NewGuid();
        Guid salesA = default, hrA = default;
        foreach (var tenant in new[] { "a", "b" })
        {
            await using var db = PgProvisioning.NewContext(cs, mode, tenant);
            var sales = SecurityModule.Create("Sales", "SALES");
            var hr = SecurityModule.Create("HR", "HR");
            db.SecurityModules.AddRange(sales, hr);
            db.SecurityPermissions.AddRange(
                SecurityPermission.Create(sales.Id, "View", "SALES.VIEW"),
                SecurityPermission.Create(sales.Id, "Edit", "SALES.EDIT"),
                SecurityPermission.Create(hr.Id, "View", "HR.VIEW"));
            if (tenant == "a")
            {
                (salesA, hrA) = (sales.Id, hr.Id);
                var plan = SubscriptionPlan.Create("Plan", "PLAN", null, 1);
                plan.Id = planId;
                db.AddRange(
                    plan,
                    SystemSubscription.Create("A", "a", planId, DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-1))),
                    SystemSubscription.Create("B", "b", planId, DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-1))),
                    SubscriptionPlanModule.Create(planId, sales.Id),
                    SubscriptionPlanModule.Create(planId, hr.Id));
            }

            await db.SaveChangesAsync();
        }

        await using (var before = PgProvisioning.NewContext(cs, mode, "b"))
        {
            (await new DbSecurityStore(before).IsModuleActiveAsync("b", "SALES")).Should().BeFalse("before the migration, tenant b's random ids do not match the plan");
        }

        await using (var admin = new NpgsqlConnection(cs))
        {
            await admin.OpenAsync();
            await using var command = admin.CreateCommand();
            command.CommandText = MigrationSql();
            await command.ExecuteNonQueryAsync();
        }

        foreach (var tenant in new[] { "a", "b" })
        {
            var modules = await ModulesAsync(cs, mode, tenant);
            modules.Should().Equal(new[]
            {
                ("HR", SecurityModuleId.FromCode("HR")),
                ("SALES", SecurityModuleId.FromCode("SALES"))
            }, $"tenant {tenant}");

            await using var db = PgProvisioning.NewContext(cs, mode, tenant);
            var permissions = await db.SecurityPermissions.AsNoTracking().ToListAsync();
            permissions.Should().HaveCount(3);
            permissions.Where(p => p.Code.StartsWith("SALES.", StringComparison.Ordinal)).Should().OnlyContain(p => p.ModuleId == SecurityModuleId.FromCode("SALES"));
            permissions.Single(p => p.Code == "HR.VIEW").ModuleId.Should().Be(SecurityModuleId.FromCode("HR"));
        }

        await using (var catalog = PgProvisioning.NewContext(cs, mode, "a"))
        {
            var mapped = await catalog.SubscriptionPlanModules.AsNoTracking().Select(m => m.ModuleId).ToListAsync();
            mapped.Should().BeEquivalentTo([SecurityModuleId.FromCode("SALES"), SecurityModuleId.FromCode("HR")], "the plan mappings were repointed");
            mapped.Should().NotContain([salesA, hrA]);
        }

        foreach (var schema in new[] { "tenant_a", "tenant_b" })
        {
            var fk = (long)(await PgProvisioning.ScalarAsync(cs,
                $"select count(*) from pg_constraint where contype='f' and conname='FK_security_permissions_security_modules_ModuleId' and conrelid='{schema}.security_permissions'::regclass and confrelid='{schema}.security_modules'::regclass"))!;
            fk.Should().Be(1, $"the foreign key is back in {schema}");
        }

        foreach (var tenant in new[] { "a", "b" })
        {
            await using var after = PgProvisioning.NewContext(cs, mode, tenant);
            var store = new DbSecurityStore(after);
            (await store.IsModuleActiveAsync(tenant, "SALES")).Should().BeTrue($"after the migration, tenant {tenant} matches the plan");
            (await store.IsModuleActiveAsync(tenant, "HR")).Should().BeTrue();
        }
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task MigrationScript_ShouldBeSafeToRunTwice(TenantSchemaMode mode)
    {
        var cs = await postgres.CreateDatabaseAsync();
        await PgProvisioning.ProvisionAsync(cs, mode, "a", "b");
        foreach (var tenant in new[] { "a", "b" })
        {
            await using var db = PgProvisioning.NewContext(cs, mode, tenant);
            db.SecurityModules.Add(SecurityModule.Create("Sales", "SALES"));
            await db.SaveChangesAsync();
        }

        for (var run = 0; run < 2; run++)
        {
            await using var admin = new NpgsqlConnection(cs);
            await admin.OpenAsync();
            await using var command = admin.CreateCommand();
            command.CommandText = MigrationSql();
            await command.ExecuteNonQueryAsync();
        }

        (await ModulesAsync(cs, mode, "a")).Should().Equal([("SALES", SecurityModuleId.FromCode("SALES"))]);
        (await ModulesAsync(cs, mode, "b")).Should().Equal([("SALES", SecurityModuleId.FromCode("SALES"))]);
    }
}
