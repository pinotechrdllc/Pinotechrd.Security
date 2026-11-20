using Microsoft.EntityFrameworkCore;
using Npgsql;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;

/// <summary>
/// Development only: provisions two tenants on first start, as a deployment pipeline would, with the owner role. Each
/// tenant gets its schema and tables, the SALES module, a "seller" role with SALES.VIEW, demo users, a plan with SALES,
/// a started subscription and an active tenant row; then the application role gets access to them.
/// </summary>
public static class SampleProvisioning
{
    /// <summary>Demo only. Never ship fixed credentials.</summary>
    public const string Password = "Sample-Passw0rd!";

    private static readonly (string Tenant, string Email, bool Seller, bool TwoFactor)[] Users =
    [
        ("tenant-a", "alice@tenant-a.test", true, false),
        ("tenant-a", "carol@tenant-a.test", false, false),
        ("tenant-a", "mfa@tenant-a.test", true, true),
        ("tenant-b", "bob@tenant-b.test", true, false),
    ];

    public static async Task EnsureProvisionedAsync(IServiceProvider services, string ownerConnection)
    {
        await using (var probe = new NpgsqlConnection(ownerConnection))
        {
            await probe.OpenAsync();
            await using var command = new NpgsqlCommand("SELECT to_regclass('public.tenants') IS NOT NULL", probe);
            if ((bool)(await command.ExecuteScalarAsync())!) return;
        }

        string[] tenants = ["tenant-a", "tenant-b"];
        for (var i = 0; i < tenants.Length; i++)
        {
            await ProvisionTenantAsync(services, ownerConnection, tenants[i], createCatalog: i == 0);
        }

        await GrantApplicationRoleAsync(ownerConnection, tenants);
    }

    private static async Task ProvisionTenantAsync(IServiceProvider services, string ownerConnection, string tenantId, bool createCatalog)
    {
        using var scope = services.CreateScope();
        var sp = scope.ServiceProvider;
        sp.GetRequiredService<ProvisioningScope>().Active = true;
        var tenant = sp.GetRequiredService<TenantContext>();
        tenant.SetTenant(tenantId);

        // 1. Schema and tables (the first tenant also creates the catalog tables).
        var tableOptions = new DbContextOptionsBuilder<SampleSecurityDbContext>().UseNpgsql(ownerConnection);
        tableOptions.UsePinotechrdSecurity(model =>
        {
            model.TenantSchemaMode = TenantSchemaMode.SearchPath;
            model.ExcludeCatalogFromMigrations = !createCatalog;
            model.MapRefreshTokens = true;
            model.MapTwoFactorAttempts = true;
        });
        await using (var tables = new SampleSecurityDbContext(tableOptions.Options, sp.GetRequiredService<ISchemaProvider>()))
        {
            // SchemaName is tenant_ plus [a-z0-9_] only (TenantIdentifier), so it is safe to quote here.
            var createSchema = $"CREATE SCHEMA IF NOT EXISTS \"{tenant.SchemaName}\"";
            await tables.Database.ExecuteSqlRawAsync(createSchema);
            await tables.Database.ExecuteSqlRawAsync(tables.Database.GenerateCreateScript());
        }

        // 2. The module and its permission, a role, and the users.
        await sp.GetRequiredService<SecuritySeeder>().SeedModuleAsync("Sales", "SALES", null, 1, [("View sales", "SALES.VIEW", null)]);
        var security = sp.GetRequiredService<IPinotechrdSecurityManager<SampleUser, SampleRole>>();
        await security.CreateRoleAsync(new SampleRole { Name = "seller" });
        var role = await security.GetRoleByNameAsync("seller");
        await security.AssignPermissionsToRoleAsync(role!.Id.ToString(), ["SALES.VIEW"]);
        foreach (var (_, email, seller, twoFactor) in Users.Where(u => u.Tenant == tenantId))
        {
            var user = new SampleUser { UserName = email, Email = email, EmailConfirmed = true, TwoFactorEnabled = twoFactor };
            await security.CreateUserAsync(user, Password, seller ? ["seller"] : []);
        }

        // 3. Catalog rows: a plan with SALES, a started subscription for this tenant id, an active tenant.
        var db = sp.GetRequiredService<SampleSecurityDbContext>();
        var plan = SubscriptionPlan.Create($"Basic {tenantId}", $"BASIC_{tenantId.ToUpperInvariant()}", null, 0m);
        db.SubscriptionPlans.Add(plan);
        db.SubscriptionPlanModules.Add(SubscriptionPlanModule.Create(plan.Id, SecurityModuleId.FromCode("SALES")));
        var subscription = SystemSubscription.Create($"Customer {tenantId}", tenantId, plan.Id, DateOnly.FromDateTime(DateTime.UtcNow));
        db.SystemSubscriptions.Add(subscription);
        var row = Tenant.Create(subscription.Id, $"Customer {tenantId}", tenantId, tenant.SchemaName!);
        row.Status = TenantStatus.Active;
        db.Tenants.Add(row);
        await db.SaveChangesAsync();
    }

    private static async Task GrantApplicationRoleAsync(string ownerConnection, IEnumerable<string> tenants)
    {
        await using var connection = new NpgsqlConnection(ownerConnection);
        await connection.OpenAsync();
        foreach (var tenant in tenants)
        {
            var schema = TenantIdentifier.ToSchemaName(tenant);
            foreach (var sql in new[]
            {
                $"REVOKE ALL ON SCHEMA \"{schema}\" FROM PUBLIC",
                $"GRANT USAGE ON SCHEMA \"{schema}\" TO sample_app",
                $"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA \"{schema}\" TO sample_app",
            })
            {
                await using var command = new NpgsqlCommand(sql, connection);
                await command.ExecuteNonQueryAsync();
            }
        }

        // The catalog is read-only for the application.
        await using var catalog = new NpgsqlCommand("GRANT SELECT ON ALL TABLES IN SCHEMA public TO sample_app", connection);
        await catalog.ExecuteNonQueryAsync();
    }
}
