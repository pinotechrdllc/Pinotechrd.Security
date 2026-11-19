using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>A cancelled token leaves no trace on a real PostgreSQL, in both schema modes.</summary>
[Collection(PostgresCollection.Name)]
public class PostgresCancellationTests(PostgresFixture postgres) : IAsyncLifetime
{
    private const string Tenant = "a";

    private readonly Dictionary<TenantSchemaMode, string> _databases = [];
    private readonly Dictionary<TenantSchemaMode, TenantDatabaseApi> _hosts = [];
    private readonly Dictionary<TenantSchemaMode, Guid> _users = [];

    public static IEnumerable<object[]> Modes() => PgProvisioning.BothModes();

    private static CancellationToken Cancelled() => new(canceled: true);

    public async Task InitializeAsync()
    {
        foreach (var mode in PgProvisioning.Modes)
        {
            var cs = await postgres.CreateDatabaseAsync();
            await PgProvisioning.ProvisionAsync(cs, mode, Tenant, "b");
            _databases[mode] = cs;

            await using (var db = PgProvisioning.NewContext(cs, mode, Tenant))
            {
                await new SecuritySeeder(db).SeedModuleAsync("Cancel", "cancel", null, 1,
                [
                    ("View", "CANCEL.VIEW", null),
                    ("Edit", "CANCEL.EDIT", null)
                ]);
                var user = new HostUser { UserName = "carol@a.test", NormalizedUserName = "CAROL@A.TEST", Email = "carol@a.test", NormalizedEmail = "CAROL@A.TEST" };
                db.Users.Add(user);
                await db.SaveChangesAsync();
                _users[mode] = user.Id;
            }

            _hosts[mode] = await TenantDatabaseApi.StartAsync(
                new Dictionary<string, string[]> { ["a"] = ["seed@a.test"], ["b"] = [] },
                mode,
                useDatabase: (options, _) => options.UseNpgsql(cs),
                provision: false);
        }
    }

    public async Task DisposeAsync()
    {
        foreach (var api in _hosts.Values) await api.DisposeAsync();
        Npgsql.NpgsqlConnection.ClearAllPools();
    }

    private static async Task<string[]> OverridesAsync(SecDb db, Guid userId)
    {
        var rows = await db.UserModulePermissions.Where(r => r.UserId == userId)
            .Select(r => new { r.Permission.Code, r.AccessType }).ToListAsync();
        return rows.Select(r => r.Code + ":" + r.AccessType).OrderBy(c => c, StringComparer.Ordinal).ToArray();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldLeaveNoUserRow_WhenTheTokenIsAlreadyCancelled(TenantSchemaMode mode)
    {
        var email = "cancel-" + Guid.NewGuid().ToString("N")[..8] + "@a.test";
        var user = new HostUser { UserName = email, Email = email, EmailConfirmed = true };

        var act = () => _hosts[mode].InTenantAsync(Tenant, sp =>
            sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>()
                .CreateUserAsync(user, TenantDatabaseApi.Password, null, Cancelled()));

        await act.Should().ThrowAsync<OperationCanceledException>();
        var found = await _hosts[mode].InTenantAsync(Tenant, async sp =>
            await sp.GetRequiredService<UserManager<HostUser>>().FindByEmailAsync(email));
        found.Should().BeNull();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ReplaceUserOverridesAsync_ShouldThrowOperationCanceledAndWriteNothing_WhenTheTokenIsAlreadyCancelled(TenantSchemaMode mode)
    {
        var userId = _users[mode];
        await using (var seed = PgProvisioning.NewContext(_databases[mode], mode, Tenant))
        {
            (await new PinotechrdSecurityManager<HostUser, HostRole>(null!, null!, seed).ReplaceUserOverridesAsync(
                userId.ToString(), [new UserPermissionOverride("CANCEL.VIEW", PermissionAccessType.Allow)])).Should().BeTrue();
        }

        await using (var db = PgProvisioning.NewContext(_databases[mode], mode, Tenant))
        {
            var act = () => new PinotechrdSecurityManager<HostUser, HostRole>(null!, null!, db).ReplaceUserOverridesAsync(
                userId.ToString(), [new UserPermissionOverride("CANCEL.EDIT", PermissionAccessType.Deny)], Cancelled());

            await act.Should().ThrowAsync<OperationCanceledException>();
        }

        await using var read = PgProvisioning.NewContext(_databases[mode], mode, Tenant);
        (await OverridesAsync(read, userId)).Should().Equal("CANCEL.VIEW:" + PermissionAccessType.Allow);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateTenantSchemaAsync_ShouldCreateASixtyThreeCharacterSchema_WhenTheTenantIdHasFiftySixCharacters(TenantSchemaMode mode)
    {
        var tenantId = "t" + Guid.NewGuid().ToString("N")[..8] + new string('x', TenantIdentifier.MaxLength - 9);
        tenantId.Length.Should().Be(56);
        var schema = TenantIdentifier.ToSchemaName(tenantId);
        schema.Length.Should().Be(63);

        await using (var db = PgProvisioning.NewContext(_databases[mode], mode, Tenant))
        {
            await new SchemaManager(db).CreateTenantSchemaAsync(tenantId);
        }

        (await PgProvisioning.ScalarAsync(_databases[mode],
            $"SELECT count(*) FROM pg_namespace WHERE nspname = '{schema}'")).Should().Be(1L);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateTenantSchemaAsync_ShouldThrowOperationCanceledAndCreateNoSchema_WhenTheTokenIsAlreadyCancelled(TenantSchemaMode mode)
    {
        var tenantId = "c" + Guid.NewGuid().ToString("N")[..8];
        var schema = TenantIdentifier.ToSchemaName(tenantId);

        await using (var db = PgProvisioning.NewContext(_databases[mode], mode, Tenant))
        {
            var act = () => new SchemaManager(db).CreateTenantSchemaAsync(tenantId, Cancelled());
            await act.Should().ThrowAsync<OperationCanceledException>();
        }

        (await PgProvisioning.ScalarAsync(_databases[mode],
            $"SELECT count(*) FROM pg_namespace WHERE nspname = '{schema}'")).Should().Be(0L);
    }
}
