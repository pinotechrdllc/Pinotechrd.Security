using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// Two tenants provisioned as the README documents, in both schema modes, on PostgreSQL 17.7: users, roles, claims,
/// permission checks and the catalog join are per tenant, and seeding is idempotent. One database per mode, shared by the tests
/// of this class (each test uses its own users, so they do not interfere).
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresTenantDataTests(PostgresFixture postgres) : IAsyncLifetime
{
    private static readonly DateOnly Yesterday = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-1));
    private readonly Dictionary<TenantSchemaMode, string> _databases = [];

    public async Task InitializeAsync()
    {
        foreach (var mode in PgProvisioning.Modes)
        {
            var cs = await postgres.CreateDatabaseAsync();
            await PgProvisioning.ProvisionAsync(cs, mode, "a", "b");
            await SeedAsync(cs, mode);
            _databases[mode] = cs;
        }
    }

    public Task DisposeAsync()
    {
        Npgsql.NpgsqlConnection.ClearAllPools();
        return Task.CompletedTask;
    }

    public static IEnumerable<object[]> Modes() => PgProvisioning.BothModes();

    /// <summary>Plan "salesplan" has the SALES module and is subscribed by tenant a; plan "hrplan" has HR and is subscribed by b.</summary>
    private static async Task SeedAsync(string cs, TenantSchemaMode mode)
    {
        await using (var catalog = PgProvisioning.NewContext(cs, mode, "a"))
        {
            var salesPlan = SubscriptionPlan.Create("Sales plan", "SALESPLAN", null, 10);
            var hrPlan = SubscriptionPlan.Create("HR plan", "HRPLAN", null, 20);
            catalog.AddRange(
                salesPlan,
                hrPlan,
                SystemSubscription.Create("A Corp", "a", salesPlan.Id, Yesterday),
                SystemSubscription.Create("B Corp", "b", hrPlan.Id, Yesterday),
                SubscriptionPlanModule.Create(salesPlan.Id, SecurityModuleId.FromCode("SALES")),
                SubscriptionPlanModule.Create(hrPlan.Id, SecurityModuleId.FromCode("HR")));
            await catalog.SaveChangesAsync();
        }

        foreach (var tenant in new[] { "a", "b" })
        {
            await using var db = PgProvisioning.NewContext(cs, mode, tenant);
            await SeedModulesAsync(db);
        }
    }

    private static async Task SeedModulesAsync(SecDb db)
    {
        var seeder = new SecuritySeeder(db);
        await seeder.SeedModuleAsync("Sales", "SALES", null, 1, [("View", "SALES.VIEW", null), ("Edit", "SALES.EDIT", null)]);
        await seeder.SeedModuleAsync("HR", "HR", null, 2, [("View", "HR.VIEW", null)]);
    }

    private SecDb Db(TenantSchemaMode mode, string tenant) => PgProvisioning.NewContext(_databases[mode], mode, tenant);

    private static async Task<HostUser> AddUserAsync(SecDb db, string name)
    {
        var user = new HostUser { Id = Guid.NewGuid(), UserName = name, NormalizedUserName = name.ToUpperInvariant(), Email = name + "@x.test", NormalizedEmail = (name + "@x.test").ToUpperInvariant() };
        db.Users.Add(user);
        await db.SaveChangesAsync();
        return user;
    }

    private static async Task<HostRole> AddRoleAsync(SecDb db, string name, params string[] permissionCodes)
    {
        var role = new HostRole { Id = Guid.NewGuid(), Name = name, NormalizedName = name.ToUpperInvariant() };
        db.Roles.Add(role);
        await db.SaveChangesAsync();
        foreach (var code in permissionCodes)
        {
            var permission = await db.SecurityPermissions.SingleAsync(p => p.Code == code);
            db.RolePermissions.Add(RolePermission.Create(role.Id, permission.Id));
        }

        await db.SaveChangesAsync();
        return role;
    }

    /// <summary>The host application's data provider, over the tenant's own tables.</summary>
    private sealed class DbDataProvider(SecDb db, string? userId, string tenant) : ISecurityDataProvider
    {
        public string? GetCurrentUserId() => userId;

        public string? GetCurrentTenantId() => tenant;

        public async Task<IEnumerable<string>> GetUserRolesAsync(string id)
        {
            var user = Guid.Parse(id);
            return await db.UserRoles.Where(r => r.UserId == user).Join(db.Roles, ur => ur.RoleId, r => r.Id, (_, r) => r.Name!).ToListAsync();
        }

        public async Task<IEnumerable<string>> GetUserPermissionsAsync(string id)
        {
            var user = Guid.Parse(id);
            return await (from ur in db.UserRoles
                          where ur.UserId == user
                          join rp in db.RolePermissions on ur.RoleId equals rp.RoleId
                          select rp.Permission.Code).ToListAsync();
        }
    }

    private static SecurityEngine Engine(SecDb db, string? userId, string tenant) =>
        new(new DbSecurityStore(db), new DbDataProvider(db, userId, tenant), SecDbFactory.Tenant(tenant));

    // ---- Where the data lives ----------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Tables_ShouldLiveInTheTenantSchemas_AndTheCatalogInPublic(TenantSchemaMode mode)
    {
        var cs = _databases[mode];

        async Task<long> Count(string schema, string table) => (long)(await PgProvisioning.ScalarAsync(cs,
            $"select count(*) from information_schema.tables where table_schema='{schema}' and table_name='{table}'"))!;

        (await Count("tenant_a", "users")).Should().Be(1);
        (await Count("tenant_b", "users")).Should().Be(1);
        (await Count("tenant_a", "security_modules")).Should().Be(1);
        (await Count("public", "users")).Should().Be(0);
        (await Count("public", "subscription_plans")).Should().Be(1);
        (await Count("tenant_a", "subscription_plans")).Should().Be(0, "the catalog is created once, not per tenant");
    }

    // ---- Users, roles, claims ----------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task User_ShouldBeFoundInItsOwnTenant_AndNotInTheOther(TenantSchemaMode mode)
    {
        var name = "alice-" + Guid.NewGuid().ToString("N")[..6];
        await using (var a = Db(mode, "a")) await AddUserAsync(a, name);

        await using var inA = Db(mode, "a");
        await using var inB = Db(mode, "b");

        (await inA.Users.AnyAsync(u => u.UserName == name)).Should().BeTrue();
        (await inB.Users.AnyAsync(u => u.UserName == name)).Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task SameUserName_ShouldBeAllowedInBothTenants_AsTwoDifferentUsers(TenantSchemaMode mode)
    {
        var name = "shared-" + Guid.NewGuid().ToString("N")[..6];
        Guid idA, idB;
        await using (var a = Db(mode, "a")) idA = (await AddUserAsync(a, name)).Id;
        await using (var b = Db(mode, "b")) idB = (await AddUserAsync(b, name)).Id;

        await using var inA = Db(mode, "a");
        await using var inB = Db(mode, "b");
        (await inA.Users.Where(u => u.UserName == name).Select(u => u.Id).SingleAsync()).Should().Be(idA);
        (await inB.Users.Where(u => u.UserName == name).Select(u => u.Id).SingleAsync()).Should().Be(idB);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task RolesAndClaims_ShouldStayInTheTenantThatCreatedThem(TenantSchemaMode mode)
    {
        var suffix = Guid.NewGuid().ToString("N")[..6];
        Guid userId;
        await using (var a = Db(mode, "a"))
        {
            var user = await AddUserAsync(a, "carol-" + suffix);
            userId = user.Id;
            var role = await AddRoleAsync(a, "manager-" + suffix);
            a.UserRoles.Add(new IdentityUserRole<Guid> { UserId = user.Id, RoleId = role.Id });
            a.UserClaims.Add(new IdentityUserClaim<Guid> { UserId = user.Id, ClaimType = "dept", ClaimValue = "sales" });
            await a.SaveChangesAsync();
        }

        await using var inA = Db(mode, "a");
        await using var inB = Db(mode, "b");
        (await inA.Roles.AnyAsync(r => r.Name == "manager-" + suffix)).Should().BeTrue();
        (await inB.Roles.AnyAsync(r => r.Name == "manager-" + suffix)).Should().BeFalse();
        (await inA.UserClaims.CountAsync(c => c.UserId == userId)).Should().Be(1);
        (await inB.UserClaims.CountAsync(c => c.UserId == userId)).Should().Be(0);
        (await inA.UserRoles.CountAsync(r => r.UserId == userId)).Should().Be(1);
        (await inB.UserRoles.CountAsync(r => r.UserId == userId)).Should().Be(0);
    }

    // ---- Permission checks and the catalog join ----------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CatalogJoin_ShouldAnswerPerTenant(TenantSchemaMode mode)
    {
        await using var a = Db(mode, "a");
        await using var b = Db(mode, "b");
        var storeA = new DbSecurityStore(a);
        var storeB = new DbSecurityStore(b);

        (await storeA.IsSubscriptionActiveAsync("a")).Should().BeTrue();
        (await storeA.IsModuleActiveAsync("a", "SALES")).Should().BeTrue();
        (await storeA.IsModuleActiveAsync("a", "HR")).Should().BeFalse("HR is not in tenant a's plan");
        (await storeB.IsModuleActiveAsync("b", "HR")).Should().BeTrue();
        (await storeB.IsModuleActiveAsync("b", "SALES")).Should().BeFalse("SALES is not in tenant b's plan");
        (await storeA.IsModuleActiveAsync("a", "NOPE")).Should().BeFalse();
        (await storeA.GetActiveModuleCodesAsync("a")).Should().BeEquivalentTo("SALES");
        (await storeB.GetActiveModuleCodesAsync("b")).Should().BeEquivalentTo("HR");
        var catalog = await storeA.GetActiveCatalogAsync("a");
        catalog.Select(m => m.Code).Should().BeEquivalentTo("SALES");
        catalog.Single().Permissions.Select(p => p.Code).Should().BeEquivalentTo("SALES.VIEW", "SALES.EDIT");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CanAccess_ShouldFollowRoleGrants_PerUserDenies_AndThePlan(TenantSchemaMode mode)
    {
        var suffix = Guid.NewGuid().ToString("N")[..6];
        Guid user;
        await using (var a = Db(mode, "a"))
        {
            var dave = await AddUserAsync(a, "dave-" + suffix);
            user = dave.Id;
            // The role grants SALES.VIEW and HR.VIEW; tenant a's plan has only SALES.
            var role = await AddRoleAsync(a, "staff-" + suffix, "SALES.VIEW", "HR.VIEW");
            a.UserRoles.Add(new IdentityUserRole<Guid> { UserId = dave.Id, RoleId = role.Id });
            await a.SaveChangesAsync();
        }

        await using (var a = Db(mode, "a"))
        {
            var engine = Engine(a, user.ToString(), "a");
            (await engine.CanAccessAsync("SALES", "VIEW")).Should().BeTrue("granted by the role, and the module is in the plan");
            (await engine.CanAccessAsync("SALES", "EDIT")).Should().BeFalse("not granted");
            (await engine.CanAccessAsync("HR", "VIEW")).Should().BeFalse("granted by the role, but the module is not in the plan");
            (await engine.GetPermissionsAsync(user.ToString())).Should().BeEquivalentTo("SALES.VIEW");
        }

        await using (var a = Db(mode, "a"))
        {
            var permission = await a.SecurityPermissions.SingleAsync(p => p.Code == "SALES.VIEW");
            a.UserModulePermissions.Add(UserModulePermission.CreateDeny(user, permission.Id));
            await a.SaveChangesAsync();
        }

        await using (var a = Db(mode, "a"))
        {
            (await Engine(a, user.ToString(), "a").CanAccessAsync("SALES", "VIEW")).Should().BeFalse("a per-user deny beats the role grant");
        }
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CanAccess_ShouldBeFalseInTheOtherTenant_ForAUserWhoOnlyExistsInOne(TenantSchemaMode mode)
    {
        var suffix = Guid.NewGuid().ToString("N")[..6];
        Guid user;
        await using (var a = Db(mode, "a"))
        {
            var erin = await AddUserAsync(a, "erin-" + suffix);
            user = erin.Id;
            var role = await AddRoleAsync(a, "staff-" + suffix, "SALES.VIEW");
            a.UserRoles.Add(new IdentityUserRole<Guid> { UserId = erin.Id, RoleId = role.Id });
            await a.SaveChangesAsync();
        }

        await using var b = Db(mode, "b");
        var engineInB = Engine(b, user.ToString(), "b");

        (await engineInB.CanAccessAsync("SALES", "VIEW")).Should().BeFalse("the user and the role grant live in tenant a's tables");
        (await engineInB.CanAccessAsync("HR", "VIEW")).Should().BeFalse();
        (await engineInB.GetPermissionsAsync(user.ToString())).Should().BeEmpty();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CanAccess_ShouldWorkInTenantB_WithItsOwnPlan(TenantSchemaMode mode)
    {
        var suffix = Guid.NewGuid().ToString("N")[..6];
        Guid user;
        await using (var b = Db(mode, "b"))
        {
            var frank = await AddUserAsync(b, "frank-" + suffix);
            user = frank.Id;
            var role = await AddRoleAsync(b, "staff-" + suffix, "HR.VIEW", "SALES.VIEW");
            b.UserRoles.Add(new IdentityUserRole<Guid> { UserId = frank.Id, RoleId = role.Id });
            await b.SaveChangesAsync();
        }

        await using var db = Db(mode, "b");
        var engine = Engine(db, user.ToString(), "b");

        (await engine.CanAccessAsync("HR", "VIEW")).Should().BeTrue();
        (await engine.CanAccessAsync("SALES", "VIEW")).Should().BeFalse("SALES is not in tenant b's plan");
    }

    // ---- Seeding -----------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Seeding_ShouldBeIdempotent_AndGiveEveryTenantTheDeterministicModuleIds(TenantSchemaMode mode)
    {
        foreach (var tenant in new[] { "a", "b" })
        {
            await using (var db = Db(mode, tenant)) await SeedModulesAsync(db);
            await using (var db = Db(mode, tenant)) await SeedModulesAsync(db);

            await using var read = Db(mode, tenant);
            var modules = await read.SecurityModules.AsNoTracking().OrderBy(m => m.Code).ToListAsync();
            modules.Select(m => m.Code).Should().Equal("HR", "SALES");
            modules.Select(m => m.Id).Should().Equal(SecurityModuleId.FromCode("HR"), SecurityModuleId.FromCode("SALES"));
            (await read.SecurityPermissions.CountAsync()).Should().Be(3, "running the seeder again adds nothing");
            var permissions = await read.SecurityPermissions.AsNoTracking().ToListAsync();
            permissions.Should().OnlyContain(p => modules.Select(m => m.Id).Contains(p.ModuleId));
            permissions.Single(p => p.Code == "HR.VIEW").ModuleId.Should().Be(SecurityModuleId.FromCode("HR"));
        }
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ForeignKeys_ShouldExistFromPermissionsToModules_InEveryTenantSchema(TenantSchemaMode mode)
    {
        var cs = _databases[mode];
        foreach (var schema in new[] { "tenant_a", "tenant_b" })
        {
            var count = (long)(await PgProvisioning.ScalarAsync(cs,
                $"select count(*) from pg_constraint where contype='f' and conrelid='{schema}.security_permissions'::regclass and confrelid='{schema}.security_modules'::regclass"))!;
            count.Should().Be(1, schema);
        }

        // The catalog has no foreign key to a tenant table (modules are matched by id).
        var catalogFks = (long)(await PgProvisioning.ScalarAsync(cs,
            "select count(*) from pg_constraint where contype='f' and conrelid='public.subscription_plan_modules'::regclass and confrelid::regclass::text like '%security_modules'"))!;
        catalogFks.Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task APermissionForAnUnknownModule_ShouldBeRejectedByTheDatabase(TenantSchemaMode mode)
    {
        await using var db = Db(mode, "a");
        db.SecurityPermissions.Add(SecurityPermission.Create(Guid.NewGuid(), "Ghost", "GHOST.VIEW"));

        var act = () => db.SaveChangesAsync();

        await act.Should().ThrowAsync<DbUpdateException>("the foreign key to security_modules is enforced");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ModuleIds_ShouldBeTheSameInEveryTenant_SoCatalogPlansMatchThem(TenantSchemaMode mode)
    {
        await using var a = Db(mode, "a");
        await using var b = Db(mode, "b");

        var idsA = await a.SecurityModules.AsNoTracking().Select(m => m.Id).ToListAsync();
        var idsB = await b.SecurityModules.AsNoTracking().Select(m => m.Id).ToListAsync();
        var planModules = await a.SubscriptionPlanModules.AsNoTracking().Select(m => m.ModuleId).ToListAsync();

        idsA.Should().BeEquivalentTo(idsB);
        planModules.Should().BeSubsetOf(idsA);
    }
}
