using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Models;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// <c>AssignPermissionsToRoleAsync</c> and <c>ReplaceUserOverridesAsync</c> under concurrency on a real PostgreSQL, in both
/// schema modes. Every concurrent caller has its own context (its own connection and transaction), as separate requests would.
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresPermissionReplaceTests(PostgresFixture postgres) : IAsyncLifetime
{
    private const string Tenant = "a";
    private const int Callers = 16;
    private const int PermissionCount = 16;

    private readonly Dictionary<TenantSchemaMode, string> _databases = [];
    private readonly Dictionary<TenantSchemaMode, (Guid Role, Guid User)> _owners = [];

    private static string Code(int index) => $"CONC.P{index:00}";

    private static string Schema => TenantIdentifier.ToSchemaName(Tenant);

    public static IEnumerable<object[]> Modes() => PgProvisioning.BothModes();

    public async Task InitializeAsync()
    {
        foreach (var mode in PgProvisioning.Modes)
        {
            var cs = await postgres.CreateDatabaseAsync();
            await PgProvisioning.ProvisionAsync(cs, mode, Tenant, "b");
            _databases[mode] = cs;

            await using var db = Db(mode);
            await new SecuritySeeder(db).SeedModuleAsync("Concurrency", "conc", null, 1,
                Enumerable.Range(0, PermissionCount).Select(i => (Name: $"P{i:00}", Code: Code(i), Description: (string?)null)));
            await CreateOwnersAsync(mode, db);
        }
    }

    public Task DisposeAsync()
    {
        NpgsqlConnection.ClearAllPools();
        return Task.CompletedTask;
    }

    private SecDb Db(TenantSchemaMode mode) => PgProvisioning.NewContext(_databases[mode], mode, Tenant);

    private async Task CreateOwnersAsync(TenantSchemaMode mode, SecDb db)
    {
        var role = new HostRole { Name = "clerk", NormalizedName = "CLERK" };
        var user = new HostUser { UserName = "carol@a.test", NormalizedUserName = "CAROL@A.TEST", Email = "carol@a.test", NormalizedEmail = "CAROL@A.TEST" };
        db.Roles.Add(role);
        db.Users.Add(user);
        await db.SaveChangesAsync();
        _owners[mode] = (role.Id, user.Id);
    }

    private static PinotechrdSecurityManager<HostUser, HostRole> Manager(SecDb db) => new(null!, null!, db);

    /// <summary>Three overlapping codes per caller, so a mix of two callers' sets is never equal to a requested set.</summary>
    private static string[] SetOf(int caller) =>
        Enumerable.Range(0, 3).Select(k => Code((caller + k) % PermissionCount)).OrderBy(c => c, StringComparer.Ordinal).ToArray();

    private static async Task<T[]> RunTogetherAsync<T>(int count, Func<int, Task<T>> work)
    {
        var gate = new TaskCompletionSource();
        var tasks = Enumerable.Range(0, count).Select(i => Task.Run(async () =>
        {
            await gate.Task;
            return await work(i);
        })).ToArray();
        gate.SetResult();
        return await Task.WhenAll(tasks);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task AssignPermissionsToRoleAsync_ShouldCompleteForEveryCaller_AndLeaveExactlyOneRequestedSet_WhenCalledConcurrently(TenantSchemaMode mode)
    {
        var roleId = _owners[mode].Role;

        var results = await RunTogetherAsync(Callers, async i =>
        {
            await using var db = Db(mode);
            return await Manager(db).AssignPermissionsToRoleAsync(roleId.ToString(), SetOf(i));
        });

        results.Should().AllSatisfy(r => r.Should().BeTrue());
        await using var read = Db(mode);
        var rows = await read.RolePermissions.Where(rp => rp.RoleId == roleId)
            .Select(rp => new { rp.PermissionId, rp.Permission.Code }).ToListAsync();
        rows.Select(r => r.PermissionId).Should().OnlyHaveUniqueItems("a role holds a permission once");
        var final = rows.Select(r => r.Code).OrderBy(c => c, StringComparer.Ordinal).ToArray();
        Enumerable.Range(0, Callers).Select(SetOf).Should().ContainEquivalentOf(final, options => options.WithStrictOrdering(),
            "the final state is exactly one of the requested sets, never a mix");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ReplaceUserOverridesAsync_ShouldCompleteForEveryCaller_AndLeaveExactlyOneRequestedSet_WhenCalledConcurrently(TenantSchemaMode mode)
    {
        var userId = _owners[mode].User;
        // Even callers allow their codes, odd callers deny them: the access type must come from the same caller as the codes.
        static UserPermissionOverride[] OverridesOf(int caller) =>
            SetOf(caller).Select(code => new UserPermissionOverride(code, caller % 2 == 0 ? PermissionAccessType.Allow : PermissionAccessType.Deny)).ToArray();

        var results = await RunTogetherAsync(Callers, async i =>
        {
            await using var db = Db(mode);
            return await Manager(db).ReplaceUserOverridesAsync(userId.ToString(), OverridesOf(i));
        });

        results.Should().AllSatisfy(r => r.Should().BeTrue());
        await using var read = Db(mode);
        var rows = await read.UserModulePermissions.Where(r => r.UserId == userId)
            .Select(r => new { r.PermissionId, r.Permission.Code, r.AccessType }).ToListAsync();
        rows.Select(r => r.PermissionId).Should().OnlyHaveUniqueItems("a user has one override per permission");
        var final = rows.Select(r => r.Code + ":" + r.AccessType).OrderBy(c => c, StringComparer.Ordinal).ToArray();
        var allowed = Enumerable.Range(0, Callers)
            .Select(i => OverridesOf(i).Select(o => o.Code + ":" + o.Access).OrderBy(c => c, StringComparer.Ordinal).ToArray());
        allowed.Should().ContainEquivalentOf(final, options => options.WithStrictOrdering());
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task AssignPermissionsToRoleAsync_ShouldLeaveExactlyOneRequestedSet_WhenEachCallerRunsInItsOwnTransaction(TenantSchemaMode mode)
    {
        var roleId = _owners[mode].Role;

        var results = await RunTogetherAsync(Callers, async i =>
        {
            await using var db = Db(mode);
            await using var transaction = await db.Database.BeginTransactionAsync();
            var ok = await Manager(db).AssignPermissionsToRoleAsync(roleId.ToString(), SetOf(i));
            await transaction.CommitAsync();
            return ok;
        });

        results.Should().AllSatisfy(r => r.Should().BeTrue());
        await using var read = Db(mode);
        var rows = await read.RolePermissions.Where(rp => rp.RoleId == roleId)
            .Select(rp => new { rp.PermissionId, rp.Permission.Code }).ToListAsync();
        rows.Select(r => r.PermissionId).Should().OnlyHaveUniqueItems();
        var final = rows.Select(r => r.Code).OrderBy(c => c, StringComparer.Ordinal).ToArray();
        Enumerable.Range(0, Callers).Select(SetOf).Should().ContainEquivalentOf(final, options => options.WithStrictOrdering());
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ReplaceUserOverridesAsync_ShouldLeaveExactlyOneRequestedSet_WhenEachCallerRunsInItsOwnTransaction(TenantSchemaMode mode)
    {
        var userId = _owners[mode].User;
        static UserPermissionOverride[] OverridesOf(int caller) =>
            SetOf(caller).Select(code => new UserPermissionOverride(code, caller % 2 == 0 ? PermissionAccessType.Allow : PermissionAccessType.Deny)).ToArray();

        var results = await RunTogetherAsync(Callers, async i =>
        {
            await using var db = Db(mode);
            await using var transaction = await db.Database.BeginTransactionAsync();
            var ok = await Manager(db).ReplaceUserOverridesAsync(userId.ToString(), OverridesOf(i));
            await transaction.CommitAsync();
            return ok;
        });

        results.Should().AllSatisfy(r => r.Should().BeTrue());
        await using var read = Db(mode);
        var rows = await read.UserModulePermissions.Where(r => r.UserId == userId)
            .Select(r => new { r.PermissionId, r.Permission.Code, r.AccessType }).ToListAsync();
        rows.Select(r => r.PermissionId).Should().OnlyHaveUniqueItems();
        var final = rows.Select(r => r.Code + ":" + r.AccessType).OrderBy(c => c, StringComparer.Ordinal).ToArray();
        var allowed = Enumerable.Range(0, Callers)
            .Select(i => OverridesOf(i).Select(o => o.Code + ":" + o.Access).OrderBy(c => c, StringComparer.Ordinal).ToArray());
        allowed.Should().ContainEquivalentOf(final, options => options.WithStrictOrdering());
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task AssignPermissionsToRoleAsync_ShouldKeepThePreviousSet_WhenACodeIsUnknown_OnPostgres(TenantSchemaMode mode)
    {
        var roleId = _owners[mode].Role;
        await using (var db = Db(mode))
        {
            (await Manager(db).AssignPermissionsToRoleAsync(roleId.ToString(), SetOf(0))).Should().BeTrue();
        }

        await using (var db = Db(mode))
        {
            (await Manager(db).AssignPermissionsToRoleAsync(roleId.ToString(), [Code(5), "CONC.MISSING"])).Should().BeFalse();
        }

        await using var read = Db(mode);
        (await read.RolePermissions.Where(rp => rp.RoleId == roleId).Select(rp => rp.Permission.Code).ToListAsync())
            .Should().BeEquivalentTo(SetOf(0));
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task RolePermissions_ShouldRejectADuplicateRoleAndPermissionPair_WithAUniqueViolation(TenantSchemaMode mode)
    {
        var roleId = _owners[mode].Role;
        await using var seed = Db(mode);
        var permissionId = await seed.Set<SecurityPermission>().Where(p => p.Code == Code(1)).Select(p => p.Id).SingleAsync();
        seed.RolePermissions.Add(RolePermission.Create(roleId, permissionId));
        await seed.SaveChangesAsync();

        await using var db = Db(mode);
        db.RolePermissions.Add(RolePermission.Create(roleId, permissionId));
        var act = () => db.SaveChangesAsync();

        var thrown = await act.Should().ThrowAsync<DbUpdateException>();
        thrown.WithInnerException<PostgresException>().Which.SqlState.Should().Be(PostgresErrorCodes.UniqueViolation);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task UserPermissions_ShouldRejectADuplicateUserAndPermissionPair_WithAUniqueViolation(TenantSchemaMode mode)
    {
        var userId = _owners[mode].User;
        await using var seed = Db(mode);
        var permissionId = await seed.Set<SecurityPermission>().Where(p => p.Code == Code(2)).Select(p => p.Id).SingleAsync();
        seed.UserModulePermissions.Add(UserModulePermission.CreateAllow(userId, permissionId));
        await seed.SaveChangesAsync();

        await using var db = Db(mode);
        db.UserModulePermissions.Add(UserModulePermission.CreateDeny(userId, permissionId));
        var act = () => db.SaveChangesAsync();

        var thrown = await act.Should().ThrowAsync<DbUpdateException>();
        thrown.WithInnerException<PostgresException>().Which.SqlState.Should().Be(PostgresErrorCodes.UniqueViolation);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task TheProvisionedTables_ShouldHaveUniqueIndexesAndTheDefaultEfColumnNames(TenantSchemaMode mode)
    {
        var cs = _databases[mode];

        async Task<string> ColumnsAsync(string table) => (string)(await PgProvisioning.ScalarAsync(cs,
            $"SELECT string_agg(column_name, ',' ORDER BY column_name) FROM information_schema.columns WHERE table_schema = '{Schema}' AND table_name = '{table}'"))!;

        async Task<long> UniqueIndexesAsync(string table, string columns) => Convert.ToInt64(await PgProvisioning.ScalarAsync(cs,
            $"SELECT count(*) FROM pg_indexes WHERE schemaname = '{Schema}' AND tablename = '{table}' AND indexdef LIKE 'CREATE UNIQUE INDEX%({columns})%'"));

        (await ColumnsAsync("role_permissions")).Should().Contain("RoleId").And.Contain("PermissionId").And.Contain("Id");
        (await ColumnsAsync("user_permissions")).Should().Contain("UserId").And.Contain("PermissionId").And.Contain("Id");
        (await UniqueIndexesAsync("role_permissions", "\"RoleId\", \"PermissionId\"")).Should().Be(1);
        (await UniqueIndexesAsync("user_permissions", "\"UserId\", \"PermissionId\"")).Should().Be(1);
    }
}
