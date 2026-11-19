using System.Data.Common;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// Side effects that must run to the end once started, on a real PostgreSQL in both schema modes. The request token is
/// cancelled from inside the operation, by an interceptor, at the step the test names.
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresUncancellableTests(PostgresFixture postgres) : IAsyncLifetime
{
    private const string Tenant = "a";

    private readonly Dictionary<TenantSchemaMode, string> _databases = [];
    private readonly Dictionary<TenantSchemaMode, TenantDatabaseApi> _hosts = [];
    private readonly CommitCanceller _commit = new();

    public static IEnumerable<object[]> Modes() => PgProvisioning.BothModes();

    private static void MapTokens(PinotechrdSecurityModelOptions o) => o.MapRefreshTokens = true;

    private static string NewToken() => "tok-" + Guid.NewGuid().ToString("N");

    public async Task InitializeAsync()
    {
        foreach (var mode in PgProvisioning.Modes)
        {
            var cs = await postgres.CreateDatabaseAsync();
            await PgProvisioning.ProvisionAsync(cs, mode, MapTokens, Tenant, "b");
            _databases[mode] = cs;

            // A host for the commit test: its context cancels the armed token just before the transaction commits.
            var hostCs = await postgres.CreateDatabaseAsync();
            await PgProvisioning.ProvisionAsync(hostCs, mode, "a", "b");
            _hosts[mode] = await TenantDatabaseApi.StartAsync(
                new Dictionary<string, string[]> { ["a"] = ["seed@a.test"], ["b"] = [] },
                mode,
                useDatabase: (options, _) => options.UseNpgsql(hostCs).AddInterceptors(_commit),
                provision: false);
        }
    }

    public async Task DisposeAsync()
    {
        foreach (var api in _hosts.Values) await api.DisposeAsync();
        Npgsql.NpgsqlConnection.ClearAllPools();
    }

    private SecDb Db(TenantSchemaMode mode, params IInterceptor[] interceptors)
    {
        var builder = new DbContextOptionsBuilder<SecDb>().UseNpgsql(_databases[mode]).AddInterceptors(interceptors);
        builder.UsePinotechrdSecurity(o =>
        {
            o.TenantSchemaMode = mode;
            MapTokens(o);
        });
        return new SecDb(builder.Options, new DbSchemaProvider(SecDbFactory.Tenant(Tenant), null));
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAsync_ShouldStillReturnReusedAndRevokeTheFamily_WhenCancelledDuringTheReplayedConsume(TenantSchemaMode mode)
    {
        var canceller = new UpdateCanceller();
        await using var db = Db(mode, canceller);
        var store = new EfRefreshTokenStore<SecDb>(db);
        var (used, sibling) = (NewToken(), NewToken());
        var family = Guid.NewGuid().ToString("N");
        var expires = DateTime.UtcNow.AddMinutes(10);
        await store.SaveAsync("user-1", Tenant, used, expires, family);
        await store.SaveAsync("user-1", Tenant, sibling, expires, family);
        (await store.ConsumeAsync(used, Tenant)).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);

        using var cts = new CancellationTokenSource();
        canceller.Arm(cts);
        var replay = await store.ConsumeAsync(used, Tenant, cts.Token);

        cts.IsCancellationRequested.Should().BeTrue("the interceptor cancelled the token on the first UPDATE");
        replay.Status.Should().Be(RefreshTokenConsumeStatus.Reused);
        await using var other = Db(mode);
        (await new EfRefreshTokenStore<SecDb>(other).ConsumeAsync(sibling, Tenant)).Status
            .Should().Be(RefreshTokenConsumeStatus.Revoked, "the reuse revoked the whole family");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAsync_ShouldThrowOperationCanceledAndChangeNothing_WhenTheTokenIsAlreadyCancelled(TenantSchemaMode mode)
    {
        await using var db = Db(mode);
        var store = new EfRefreshTokenStore<SecDb>(db);
        var token = NewToken();
        await store.SaveAsync("user-1", Tenant, token, DateTime.UtcNow.AddMinutes(10));

        var act = () => store.ConsumeAsync(token, Tenant, new CancellationToken(canceled: true));

        await act.Should().ThrowAsync<OperationCanceledException>();
        (await store.ConsumeAsync(token, Tenant)).Status.Should().Be(RefreshTokenConsumeStatus.Consumed,
            "the cancelled call consumed nothing");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task CreateUserAsync_ShouldReturnTrueAndKeepTheUser_WhenCancelledJustBeforeTheCommit(TenantSchemaMode mode)
    {
        var email = "commit-" + Guid.NewGuid().ToString("N")[..8] + "@a.test";
        var user = new HostUser { UserName = email, Email = email, EmailConfirmed = true };
        using var cts = new CancellationTokenSource();
        _commit.Arm(cts);
        try
        {
            var ok = await _hosts[mode].InTenantAsync(Tenant, sp =>
                sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>()
                    .CreateUserAsync(user, TenantDatabaseApi.Password, null, cts.Token));

            ok.Should().BeTrue();
            cts.IsCancellationRequested.Should().BeTrue("the interceptor cancelled the token before the commit");
        }
        finally
        {
            _commit.Disarm();
        }

        var stored = await _hosts[mode].InTenantAsync(Tenant, async sp =>
            await sp.GetRequiredService<UserManager<HostUser>>().FindByEmailAsync(email));
        stored.Should().NotBeNull("the work committed, so the caller must not be told it was cancelled");
    }

    /// <summary>Cancels the armed token on the first UPDATE the context runs.</summary>
    private sealed class UpdateCanceller : DbCommandInterceptor
    {
        private CancellationTokenSource? _cts;

        public void Arm(CancellationTokenSource cts) => _cts = cts;

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command, CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (_cts is { } cts && command.CommandText.TrimStart().StartsWith("UPDATE", StringComparison.OrdinalIgnoreCase))
            {
                _cts = null;
                cts.Cancel();
            }

            return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
        }
    }

    /// <summary>Cancels the armed token when a transaction is about to commit.</summary>
    private sealed class CommitCanceller : DbTransactionInterceptor
    {
        private volatile CancellationTokenSource? _cts;

        public void Arm(CancellationTokenSource cts) => _cts = cts;

        public void Disarm() => _cts = null;

        public override ValueTask<InterceptionResult> TransactionCommittingAsync(
            DbTransaction transaction, TransactionEventData eventData, InterceptionResult result, CancellationToken cancellationToken = default)
        {
            _cts?.Cancel();
            return base.TransactionCommittingAsync(transaction, eventData, result, cancellationToken);
        }
    }
}
