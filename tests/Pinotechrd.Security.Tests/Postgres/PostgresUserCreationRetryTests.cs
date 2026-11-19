using System.Data.Common;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// <c>CreateUserAsync</c> on a context with a retrying execution strategy, in both schema modes. A transaction interceptor throws a
/// retryable exception once, either before the commit (the work is rolled back and retried) or after it (the work is stored, and the
/// strategy must recognise that instead of creating the user twice).
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresUserCreationRetryTests(PostgresFixture postgres) : IAsyncLifetime
{
    private const string Tenant = "a";

    private readonly Dictionary<TenantSchemaMode, TenantDatabaseApi> _hosts = [];
    private readonly OneShotCommitFailure _failure = new();

    public async Task InitializeAsync()
    {
        foreach (var mode in PgProvisioning.Modes)
        {
            var cs = await postgres.CreateDatabaseAsync();
            await PgProvisioning.ProvisionAsync(cs, mode, "a");
            _hosts[mode] = await TenantDatabaseApi.StartAsync(
                new Dictionary<string, string[]> { ["a"] = ["seed@a.test"] },
                mode,
                configureOptions: options => options.AddInterceptors(_failure),
                useDatabase: (options, _) => options.UseNpgsql(cs, o => o.EnableRetryOnFailure(3, TimeSpan.FromMilliseconds(50), null)),
                provision: false);
        }
    }

    public async Task DisposeAsync()
    {
        foreach (var api in _hosts.Values) await api.DisposeAsync();
        Npgsql.NpgsqlConnection.ClearAllPools();
    }

    public static IEnumerable<object[]> Modes() => PgProvisioning.BothModes();

    private static async Task<(string Role, string Email)> ArrangeAsync(TenantDatabaseApi api)
    {
        var role = "role-" + Guid.NewGuid().ToString("N")[..8];
        await api.InTenantAsync(Tenant, async sp =>
        {
            (await sp.GetRequiredService<RoleManager<HostRole>>().CreateAsync(new HostRole { Name = role })).Succeeded.Should().BeTrue();
            return 0;
        });
        return (role, "retry-" + Guid.NewGuid().ToString("N")[..8] + "@a.test");
    }

    private static Task<bool> CreateAsync(TenantDatabaseApi api, string email, string role) =>
        api.InTenantAsync(Tenant, sp => sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>()
            .CreateUserAsync(new HostUser { UserName = email, Email = email, EmailConfirmed = true }, TenantDatabaseApi.Password, [role]));

    private static async Task AssertOneUserWithTheRoleAsync(TenantDatabaseApi api, string email, string role)
    {
        var (users, roles, rows) = await api.InTenantAsync(Tenant, async sp =>
        {
            var db = sp.GetRequiredService<SecDb>();
            var found = await db.Users.Where(u => u.Email == email).ToListAsync();
            var names = found.Count == 0 ? [] : await sp.GetRequiredService<UserManager<HostUser>>().GetRolesAsync(found[0]);
            var ids = found.Select(u => u.Id).ToList();
            return (found.Count, names, await db.UserRoles.CountAsync(r => ids.Contains(r.UserId)));
        });
        users.Should().Be(1);
        roles.Should().BeEquivalentTo([role]);
        rows.Should().Be(1);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldReturnTrueWithOneUser_WhenACommitReportsATransientErrorAfterItWasStored(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var (role, email) = await ArrangeAsync(api);
        _failure.Arm(afterCommit: true);

        var created = await CreateAsync(api, email, role);

        _failure.Fired.Should().BeTrue("the interceptor must have thrown, otherwise the test proves nothing");
        created.Should().BeTrue();
        await AssertOneUserWithTheRoleAsync(api, email, role);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldRetryAndReturnTrueWithOneUser_WhenACommitFailsTransientlyBeforeItWasStored(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var (role, email) = await ArrangeAsync(api);
        _failure.Arm(afterCommit: false);

        var created = await CreateAsync(api, email, role);

        _failure.Fired.Should().BeTrue("the interceptor must have thrown, otherwise the test proves nothing");
        created.Should().BeTrue();
        await AssertOneUserWithTheRoleAsync(api, email, role);
    }

    /// <summary>Throws a retryable <see cref="TimeoutException"/> once around a commit, when armed.</summary>
    private sealed class OneShotCommitFailure : DbTransactionInterceptor
    {
        private int _armed; // 0 none, 1 before commit, 2 after commit

        public bool Fired { get; private set; }

        public void Arm(bool afterCommit)
        {
            Fired = false;
            Volatile.Write(ref _armed, afterCommit ? 2 : 1);
        }

        public override ValueTask<InterceptionResult> TransactionCommittingAsync(
            DbTransaction transaction,
            TransactionEventData eventData,
            InterceptionResult result,
            CancellationToken cancellationToken = default)
        {
            if (Interlocked.CompareExchange(ref _armed, 0, 1) == 1)
            {
                Fired = true;
                throw new TimeoutException("simulated transient failure before commit");
            }

            return base.TransactionCommittingAsync(transaction, eventData, result, cancellationToken);
        }

        public override Task TransactionCommittedAsync(
            DbTransaction transaction,
            TransactionEndEventData eventData,
            CancellationToken cancellationToken = default)
        {
            if (Interlocked.CompareExchange(ref _armed, 0, 2) == 2)
            {
                Fired = true;
                throw new TimeoutException("simulated transient failure after commit");
            }

            return base.TransactionCommittedAsync(transaction, eventData, cancellationToken);
        }
    }
}
