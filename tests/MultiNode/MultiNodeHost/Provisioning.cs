using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;

/// <summary>
/// What a deployment pipeline does, with the owner role: the README's ProvisionTenantAsync for each tenant, then the
/// grants of README "Database roles and poolers" for the tenant's own role.
/// </summary>
public static class Provisioning
{
    public const string Password = "Multinode-Passw0rd!";

    public static readonly (string Tenant, string Email, bool TwoFactor)[] Users =
    [
        ("acme", "admin@acme.test", false),
        ("acme", "mfa@acme.test", true),
        ("acme", "mfa-limit@acme.test", true),
        ("acme", "other@acme.test", false),
        ("globex", "admin@globex.test", false),
    ];

    public static async Task RunAsync(IServiceProvider services, Settings settings)
    {
        for (var i = 0; i < Settings.Tenants.Length; i++)
        {
            await ProvisionTenantAsync(services, settings, Settings.Tenants[i], createCatalog: i == 0);
        }

        await GrantAsync(settings);
        Console.WriteLine($"Provisioned {string.Join(", ", Settings.Tenants)} in {settings.Mode} mode.");
    }

    private static async Task ProvisionTenantAsync(IServiceProvider services, Settings settings, string tenantId, bool createCatalog)
    {
        using var scope = services.CreateScope();
        var sp = scope.ServiceProvider;
        var tenant = sp.GetRequiredService<TenantContext>();
        tenant.SetTenant(tenantId);

        // 1. Schema and tables (the first tenant also creates the catalog tables).
        var tableOptions = new DbContextOptionsBuilder<AppDb>().UseNpgsql(settings.OwnerConnection);
        tableOptions.UsePinotechrdSecurity(model =>
        {
            model.TenantSchemaMode = settings.Mode;
            model.ExcludeCatalogFromMigrations = !createCatalog;
            model.MapRefreshTokens = true;
            model.MapTwoFactorAttempts = true;
        });
        await using (var tables = new AppDb(tableOptions.Options, sp.GetRequiredService<ISchemaProvider>()))
        {
            // SchemaName is tenant_ plus [a-z0-9_] only (TenantIdentifier), so it is safe to quote here.
            var createSchema = $"CREATE SCHEMA IF NOT EXISTS \"{tenant.SchemaName}\"";
            await tables.Database.ExecuteSqlRawAsync(createSchema);
            await tables.Database.ExecuteSqlRawAsync(tables.Database.GenerateCreateScript());
        }

        // 2. Module, permission, role and users.
        await sp.GetRequiredService<SecuritySeeder>().SeedModuleAsync("Sales", "SALES", null, 1, [("View sales", "SALES.VIEW", null)]);
        var security = sp.GetRequiredService<IPinotechrdSecurityManager<AppUser, AppRole>>();
        await security.CreateRoleAsync(new AppRole { Name = "seller" });
        var role = await security.GetRoleByNameAsync("seller");
        if (!await security.AssignPermissionsToRoleAsync(role!.Id.ToString(), ["SALES.VIEW"])) throw new InvalidOperationException("Permission assignment failed.");
        foreach (var (_, email, twoFactor) in Users.Where(u => u.Tenant == tenantId))
        {
            var user = new AppUser { UserName = email, Email = email, EmailConfirmed = true, TwoFactorEnabled = twoFactor };
            if (!await security.CreateUserAsync(user, Password, ["seller"])) throw new InvalidOperationException($"User {email} was not created.");
        }

        // 3. Catalog rows: a plan with the module, a started subscription, an active tenant.
        var db = sp.GetRequiredService<AppDb>();
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

    private static async Task GrantAsync(Settings settings)
    {
        await using var connection = new NpgsqlConnection(settings.OwnerConnection);
        await connection.OpenAsync();

        async Task ExecAsync(string sql)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            await command.ExecuteNonQueryAsync();
        }

        foreach (var tenant in Settings.Tenants)
        {
            var schema = TenantIdentifier.ToSchemaName(tenant);
            var role = Settings.RoleOf(tenant);
            await ExecAsync($"REVOKE ALL ON SCHEMA \"{schema}\" FROM PUBLIC");
            await ExecAsync($"GRANT USAGE ON SCHEMA \"{schema}\" TO {role}");
            await ExecAsync($"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA \"{schema}\" TO {role}");
            await ExecAsync($"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {role}");
        }

        await ExecAsync("GRANT SELECT ON ALL TABLES IN SCHEMA public TO catalog_app");
    }
}
