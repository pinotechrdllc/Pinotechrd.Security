using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// The persistent two-factor attempt store (<c>EfTwoFactorAttemptStore</c>) on a real PostgreSQL, in both schema modes. The contract cases
/// are the ones of <c>InMemoryTwoFactorAttemptStoreTests</c>; the rest prove what only a shared database can: atomic counting under
/// concurrency, a limit shared by several hosts, hashed storage and tenant-schema-only tables. Each test has its own databases.
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresTwoFactorAttemptStoreTests(PostgresFixture postgres) : IAsyncLifetime
{
    private const string TenantA = "a";
    private const string TenantB = "b";

    private readonly Dictionary<TenantSchemaMode, string> _databases = [];
    private readonly List<SecDb> _contexts = [];
    private readonly List<string> _directories = [];

    public async Task InitializeAsync()
    {
        foreach (var mode in PgProvisioning.Modes)
        {
            var cs = await postgres.CreateDatabaseAsync();
            await PgProvisioning.ProvisionAsync(cs, mode, MapAttempts, TenantA, TenantB);
            _databases[mode] = cs;
        }
    }

    public async Task DisposeAsync()
    {
        foreach (var context in _contexts) await context.DisposeAsync();
        foreach (var directory in _directories)
        {
            try { Directory.Delete(directory, recursive: true); } catch (IOException) { }
        }
    }

    public static IEnumerable<object[]> Modes() => PgProvisioning.BothModes();

    private static void MapAttempts(PinotechrdSecurityModelOptions o) => o.MapTwoFactorAttempts = true;

    private static string NewChallenge() => "challenge-" + Guid.NewGuid().ToString("N");

    private static string Schema(string tenant) => TenantIdentifier.ToSchemaName(tenant);

    private static DateTimeOffset InFiveMinutes() => DateTimeOffset.UtcNow.AddMinutes(5);

    private SecDb Db(TenantSchemaMode mode, string tenant)
    {
        var db = PgProvisioning.NewContext(_databases[mode], mode, tenant, MapAttempts);
        _contexts.Add(db);
        return db;
    }

    private EfTwoFactorAttemptStore<SecDb> Store(TenantSchemaMode mode, string tenant = TenantA) => new(Db(mode, tenant));

    private async Task<long> CountAsync(TenantSchemaMode mode, string sql) =>
        Convert.ToInt64(await PgProvisioning.ScalarAsync(_databases[mode], sql));

    private static string Table(string tenant) => $"\"{Schema(tenant)}\".two_factor_attempts";

    // ---- Contract parity with InMemoryTwoFactorAttemptStore ----------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task RegisterAttemptAsync_ShouldCountPerChallenge(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var (a, b) = (NewChallenge(), NewChallenge());
        var expires = InFiveMinutes();

        (await store.RegisterAttemptAsync(a, expires)).Should().Be(1);
        (await store.RegisterAttemptAsync(a, expires)).Should().Be(2);
        (await store.RegisterAttemptAsync(b, expires)).Should().Be(1);
        (await store.RegisterAttemptAsync(a, expires)).Should().Be(3);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task RegisterAttemptAsync_ShouldCountAcrossSeparateContextsOfTheSameDatabase(TenantSchemaMode mode)
    {
        var challenge = NewChallenge();
        var expires = InFiveMinutes();

        (await Store(mode).RegisterAttemptAsync(challenge, expires)).Should().Be(1);
        (await Store(mode).RegisterAttemptAsync(challenge, expires)).Should().Be(2);
        (await Store(mode).RegisterAttemptAsync(challenge, expires)).Should().Be(3);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task RegisterAttemptAsync_ShouldReturnIntMaxValue_AfterTheChallengeIsExhausted(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var challenge = NewChallenge();
        var expires = InFiveMinutes();
        await store.RegisterAttemptAsync(challenge, expires);

        await store.ExhaustAsync(challenge, expires);

        (await store.RegisterAttemptAsync(challenge, expires)).Should().Be(int.MaxValue);
        (await store.RegisterAttemptAsync(challenge, expires)).Should().Be(int.MaxValue);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ExhaustAsync_ShouldSpendAChallengeThatHasNeverBeenUsed_AndNotTouchOthers(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var (spent, other) = (NewChallenge(), NewChallenge());
        var expires = InFiveMinutes();

        await store.ExhaustAsync(spent, expires);

        (await store.RegisterAttemptAsync(spent, expires)).Should().Be(int.MaxValue);
        (await store.RegisterAttemptAsync(other, expires)).Should().Be(1);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ExhaustAsync_ShouldBeIdempotent(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var challenge = NewChallenge();
        var expires = InFiveMinutes();

        await store.ExhaustAsync(challenge, expires);
        var again = () => store.ExhaustAsync(challenge, expires);

        await again.Should().NotThrowAsync();
        (await store.RegisterAttemptAsync(challenge, expires)).Should().Be(int.MaxValue);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ExhaustAsync_ShouldSpendTheChallengeForOtherContexts(TenantSchemaMode mode)
    {
        var challenge = NewChallenge();
        var expires = InFiveMinutes();
        await Store(mode).RegisterAttemptAsync(challenge, expires);

        await Store(mode).ExhaustAsync(challenge, expires);

        (await Store(mode).RegisterAttemptAsync(challenge, expires)).Should().Be(int.MaxValue);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task RegisterAttemptAsync_ShouldStartCountingAgain_WhenTheRowWasPurged(TenantSchemaMode mode)
    {
        // A purged row (the application deleted it) is simply a new challenge for the next call.
        var store = Store(mode);
        var challenge = NewChallenge();
        var expires = InFiveMinutes();
        await store.RegisterAttemptAsync(challenge, expires);
        await store.RegisterAttemptAsync(challenge, expires);
        await PgProvisioning.ExecuteAsync(_databases[mode], $"DELETE FROM {Table(TenantA)}");

        (await store.RegisterAttemptAsync(challenge, expires)).Should().Be(1);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task RegisterAttemptAsync_ShouldKeepChallengesOfDifferentTenantSchemasIndependent(TenantSchemaMode mode)
    {
        var challenge = NewChallenge();
        var expires = InFiveMinutes();

        (await Store(mode, TenantA).RegisterAttemptAsync(challenge, expires)).Should().Be(1);
        (await Store(mode, TenantA).RegisterAttemptAsync(challenge, expires)).Should().Be(2);
        (await Store(mode, TenantB).RegisterAttemptAsync(challenge, expires)).Should().Be(1);
    }

    // ---- Concurrency -------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task RegisterAttemptAsync_ShouldNeverReturnLessThanTheTrueOrdinal_When50ContextsRegisterTheSameChallenge(TenantSchemaMode mode)
    {
        for (var trial = 0; trial < 2; trial++)
        {
            var challenge = NewChallenge();
            var expires = InFiveMinutes();
            var stores = Enumerable.Range(0, 50).Select(_ => Store(mode)).ToArray();
            using var gate = new ManualResetEventSlim(false);

            var tasks = stores.Select(store => Task.Run(async () =>
            {
                gate.Wait();
                return await store.RegisterAttemptAsync(challenge, expires);
            })).ToArray();
            gate.Set();
            var results = await Task.WhenAll(tasks);

            var sorted = results.OrderBy(r => r).ToArray();
            for (var i = 0; i < sorted.Length; i++)
            {
                sorted[i].Should().BeGreaterThanOrEqualTo(i + 1, $"trial {trial}: the {i + 1}th attempt must never be told it is an earlier one");
            }

            var hash = $"sha256(convert_to('{challenge}', 'UTF8'))";
            (await CountAsync(mode, $"SELECT count FROM {Table(TenantA)} WHERE challenge_hash = {hash}")).Should().Be(50, $"trial {trial}");
            (await CountAsync(mode, $"SELECT count(*) FROM {Table(TenantA)} WHERE challenge_hash = {hash}")).Should().Be(1, "one row per challenge");
        }
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ExhaustAsync_ShouldSpendTheChallenge_WhenCalledConcurrentlyWithAttempts(TenantSchemaMode mode)
    {
        var challenge = NewChallenge();
        var expires = InFiveMinutes();
        var stores = Enumerable.Range(0, 20).Select(_ => Store(mode)).ToArray();
        using var gate = new ManualResetEventSlim(false);

        var tasks = stores.Select((store, i) => Task.Run(async () =>
        {
            gate.Wait();
            if (i == 10) await store.ExhaustAsync(challenge, expires);
            else await store.RegisterAttemptAsync(challenge, expires);
        })).ToArray();
        gate.Set();
        await Task.WhenAll(tasks);

        (await Store(mode).RegisterAttemptAsync(challenge, expires)).Should().Be(int.MaxValue);
    }

    // ---- Storage -----------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Database_ShouldKeepOnlyTheSha256OfEachChallenge_AsA32ByteKey(TenantSchemaMode mode)
    {
        var challenge = "plain-" + Guid.NewGuid().ToString("N");
        await Store(mode).RegisterAttemptAsync(challenge, InFiveMinutes());
        var table = Table(TenantA);

        var wrongLength = await CountAsync(mode, $"SELECT count(*) FROM {table} WHERE octet_length(challenge_hash) <> 32");
        var hashed = await CountAsync(mode, $"SELECT count(*) FROM {table} WHERE challenge_hash = sha256(convert_to('{challenge}', 'UTF8'))");

        wrongLength.Should().Be(0);
        hashed.Should().Be(1, "the primary key is the SHA-256 of the UTF-8 challenge id");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Database_ShouldNotContainTheChallengeValueInAnyColumn(TenantSchemaMode mode)
    {
        var challenge = "plain-" + Guid.NewGuid().ToString("N");
        await Store(mode).RegisterAttemptAsync(challenge, InFiveMinutes());
        await Store(mode).ExhaustAsync(challenge, InFiveMinutes());

        var withValue = await CountAsync(mode, $"SELECT count(*) FROM {Table(TenantA)} t WHERE t::text LIKE '%{challenge}%'");
        var rows = await CountAsync(mode, $"SELECT count(*) FROM {Table(TenantA)} WHERE challenge_hash = sha256(convert_to('{challenge}', 'UTF8'))");

        withValue.Should().Be(0);
        rows.Should().Be(1, "the challenge was stored");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Database_ShouldStoreTheCountExhaustedFlagAndExpiry(TenantSchemaMode mode)
    {
        var challenge = NewChallenge();
        var expires = DateTimeOffset.UtcNow.AddMinutes(7);
        var hash = $"sha256(convert_to('{challenge}', 'UTF8'))";
        var store = Store(mode);

        await store.RegisterAttemptAsync(challenge, expires);
        await store.RegisterAttemptAsync(challenge, expires);

        (await CountAsync(mode, $"SELECT count FROM {Table(TenantA)} WHERE challenge_hash = {hash}")).Should().Be(2);
        (await PgProvisioning.ScalarAsync(_databases[mode], $"SELECT exhausted FROM {Table(TenantA)} WHERE challenge_hash = {hash}")).Should().Be(false);
        var stored = (DateTime)(await PgProvisioning.ScalarAsync(_databases[mode], $"SELECT expires_at FROM {Table(TenantA)} WHERE challenge_hash = {hash}"))!;
        stored.ToUniversalTime().Should().BeCloseTo(expires.UtcDateTime, TimeSpan.FromSeconds(2));

        await store.ExhaustAsync(challenge, expires);

        (await PgProvisioning.ScalarAsync(_databases[mode], $"SELECT exhausted FROM {Table(TenantA)} WHERE challenge_hash = {hash}")).Should().Be(true);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Table_ShouldExistInEveryTenantSchemaOnly_NeverInTheCatalogSchema(TenantSchemaMode mode)
    {
        await using var connection = new NpgsqlConnection(_databases[mode]);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT table_schema FROM information_schema.tables WHERE table_name = 'two_factor_attempts' ORDER BY 1";
        var schemas = new List<string>();
        await using (var reader = await command.ExecuteReaderAsync())
        {
            while (await reader.ReadAsync()) schemas.Add(reader.GetString(0));
        }

        schemas.Should().BeEquivalentTo([Schema(TenantA), Schema(TenantB)]);
        schemas.Should().NotContain("public");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Attempts_ShouldBeStoredInTheTenantSchemaOfTheContextOnly(TenantSchemaMode mode)
    {
        var challenge = NewChallenge();
        await Store(mode, TenantA).RegisterAttemptAsync(challenge, InFiveMinutes());
        var hash = $"sha256(convert_to('{challenge}', 'UTF8'))";

        var inA = await CountAsync(mode, $"SELECT count(*) FROM {Table(TenantA)} WHERE challenge_hash = {hash}");
        var inB = await CountAsync(mode, $"SELECT count(*) FROM {Table(TenantB)} WHERE challenge_hash = {hash}");

        inA.Should().Be(1);
        inB.Should().Be(0);
    }

    // ---- Shared context ----------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task StoreCalls_ShouldNotFlushOtherTrackedChangesOfTheSharedContext(TenantSchemaMode mode)
    {
        var db = Db(mode, TenantA);
        var store = new EfTwoFactorAttemptStore<SecDb>(db);
        var code = "PENDING" + Guid.NewGuid().ToString("N")[..8].ToUpperInvariant();
        var pending = new SecurityModule { Id = SecurityModuleId.FromCode(code), Code = code, Name = "Pending", TenantId = TenantA };
        db.SecurityModules.Add(pending);
        var challenge = NewChallenge();
        var expires = InFiveMinutes();

        (await store.RegisterAttemptAsync(challenge, expires)).Should().Be(1);
        (await store.RegisterAttemptAsync(challenge, expires)).Should().Be(2);
        await store.ExhaustAsync(NewChallenge(), expires);

        db.Entry(pending).State.Should().Be(EntityState.Added, "the store must neither save nor discard the application's pending changes");
        (await Db(mode, TenantA).SecurityModules.AnyAsync(m => m.Code == code)).Should().BeFalse("the pending entity was never written");
    }

    // ---- Flag off ----------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task EveryStoreMethod_ShouldThrowInvalidOperationMentioningMapTwoFactorAttempts_WhenTheModelDoesNotMapTheTable(TenantSchemaMode mode)
    {
        await using var db = PgProvisioning.NewContext(_databases[mode], mode, TenantA);
        var store = new EfTwoFactorAttemptStore<SecDb>(db);
        var expires = InFiveMinutes();

        var calls = new Func<Task>[]
        {
            () => store.RegisterAttemptAsync("c", expires),
            () => store.ExhaustAsync("c", expires)
        };

        foreach (var call in calls)
        {
            await call.Should().ThrowAsync<InvalidOperationException>().WithMessage("*MapTwoFactorAttempts*");
        }
    }

    // ---- Transactions ------------------------------------------------------------------------

    private static async Task AssertBothMethodsRefuseAsync(EfTwoFactorAttemptStore<SecDb> store)
    {
        var expires = InFiveMinutes();
        var register = () => store.RegisterAttemptAsync("c-" + Guid.NewGuid().ToString("N"), expires);
        var exhaust = () => store.ExhaustAsync("c-" + Guid.NewGuid().ToString("N"), expires);

        await register.Should().ThrowAsync<InvalidOperationException>().WithMessage("*transaction*");
        await exhaust.Should().ThrowAsync<InvalidOperationException>().WithMessage("*transaction*");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task StoreMethods_ShouldThrowAndWriteNothing_WhenTheContextHasATransaction(TenantSchemaMode mode)
    {
        var db = Db(mode, TenantA);
        var store = new EfTwoFactorAttemptStore<SecDb>(db);

        await using (var transaction = await db.Database.BeginTransactionAsync())
        {
            await AssertBothMethodsRefuseAsync(store);
            await transaction.RollbackAsync();
        }

        (await CountAsync(mode, $"SELECT count(*) FROM {Table(TenantA)}")).Should().Be(0, "nothing was written, committed or not");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task StoreMethods_ShouldThrowAndWriteNothing_WhenInsideATransactionScope(TenantSchemaMode mode)
    {
        var store = Store(mode);

        using (var scope = new System.Transactions.TransactionScope(System.Transactions.TransactionScopeAsyncFlowOption.Enabled))
        {
            await AssertBothMethodsRefuseAsync(store);
        }

        (await CountAsync(mode, $"SELECT count(*) FROM {Table(TenantA)}")).Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task StoreMethods_ShouldWorkAgain_AfterTheTransactionEnded(TenantSchemaMode mode)
    {
        var db = Db(mode, TenantA);
        var store = new EfTwoFactorAttemptStore<SecDb>(db);
        await using (var transaction = await db.Database.BeginTransactionAsync())
        {
            await transaction.RollbackAsync();
        }

        (await store.RegisterAttemptAsync(NewChallenge(), InFiveMinutes())).Should().Be(1);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task VerifyTwoFactorCodeAsync_ShouldThrowInsteadOfCounting_WhenCalledInsideAnApplicationTransaction(TenantSchemaMode mode)
    {
        var keys = NewKeyDirectory();
        await using var host = await StartHostAsync(mode, keys);
        var email = await NewTwoFactorUserAsync(host);
        var token = await host.LoginForTwoFactorTokenAsync(email, TenantA);

        for (var round = 0; round < 8; round++)
        {
            var act = () => host.InTenantAsync(TenantA, async sp =>
            {
                var db = sp.GetRequiredService<SecDb>();
                await using var transaction = await db.Database.BeginTransactionAsync();
                try
                {
                    return await sp.GetRequiredService<IPinotechrdAuthManager<HostUser>>()
                        .VerifyTwoFactorCodeAsync(token, "Email", "000000", TenantA);
                }
                finally
                {
                    await transaction.RollbackAsync();
                }
            });

            await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*transaction*", $"round {round}: the attempt is refused, never silently uncounted");
        }

        (await CountAsync(mode, $"SELECT count(*) FROM {Table(TenantA)}")).Should().Be(0);
        var correct = await CorrectCodeAsync(host, email);
        (await VerifyAsync(host, token, correct)).Succeeded.Should().BeTrue("outside a transaction the token still works");
    }

    // ---- Several hosts on one database -------------------------------------------------------

    private string NewKeyDirectory()
    {
        var directory = Path.Combine(Path.GetTempPath(), "pinotechrd-dp-keys-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        _directories.Add(directory);
        return directory;
    }

    private async Task<TenantDatabaseApi> StartHostAsync(TenantSchemaMode mode, string keyDirectory, bool withUser = false) =>
        await TenantDatabaseApi.StartAsync(
            new Dictionary<string, string[]> { [TenantA] = withUser ? ["seed@a.test"] : [] },
            mode,
            configureOptions: options => options.UsePinotechrdSecurity(o =>
            {
                o.TenantSchemaMode = mode;
                o.MapTwoFactorAttempts = true;
            }),
            useDatabase: (options, _) => options.UseNpgsql(_databases[mode]),
            provision: false,
            configureBuilder: builder =>
            {
                builder.Services.AddPinotechrdEfTwoFactorAttemptStore<SecDb>();
                builder.Services.AddDataProtection()
                    .PersistKeysToFileSystem(new DirectoryInfo(keyDirectory))
                    .SetApplicationName("pinotechrd-two-factor-tests");
            });

    private static async Task<string> NewTwoFactorUserAsync(TenantDatabaseApi api)
    {
        var email = "tf-" + Guid.NewGuid().ToString("N")[..8] + "@a.test";
        await api.InTenantAsync(TenantA, async sp =>
        {
            var created = await sp.GetRequiredService<UserManager<HostUser>>().CreateAsync(
                new HostUser { UserName = email, Email = email, EmailConfirmed = true, TwoFactorEnabled = true }, TenantDatabaseApi.Password);
            created.Succeeded.Should().BeTrue();
            return 0;
        });
        return email;
    }

    private static Task<AuthResult> VerifyAsync(TenantDatabaseApi api, string token, string code) =>
        api.InTenantAsync(TenantA, sp => sp.GetRequiredService<IPinotechrdAuthManager<HostUser>>()
            .VerifyTwoFactorCodeAsync(token, "Email", code, TenantA));

    private static Task<string> CorrectCodeAsync(TenantDatabaseApi api, string email) =>
        api.InTenantAsync(TenantA, async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            return await users.GenerateTwoFactorTokenAsync((await users.FindByEmailAsync(email))!, "Email");
        });

    // The account lockout would also refuse further codes; lifting it isolates the limit of the attempt store.
    private static Task LiftLockoutAsync(TenantDatabaseApi api, string email) =>
        api.InTenantAsync(TenantA, async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            var user = (await users.FindByEmailAsync(email))!;
            (await users.SetLockoutEndDateAsync(user, null)).Succeeded.Should().BeTrue();
            (await users.ResetAccessFailedCountAsync(user)).Succeeded.Should().BeTrue();
            return 0;
        });

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task WrongCodesSplitAcrossTwoHostsSharingKeys_ShouldBeLimitedToFiveInTotal_ThenRefusedOnBothHosts(TenantSchemaMode mode)
    {
        var keys = NewKeyDirectory();
        await using var hostA = await StartHostAsync(mode, keys);
        await using var hostB = await StartHostAsync(mode, keys);
        var email = await NewTwoFactorUserAsync(hostA);
        var token = await hostA.LoginForTwoFactorTokenAsync(email, TenantA);

        foreach (var host in new[] { hostA, hostB, hostA, hostB, hostA })
        {
            (await VerifyAsync(host, token, "000000")).Succeeded.Should().BeFalse();
        }

        (await CountAsync(mode, $"SELECT count FROM {Table(TenantA)}")).Should().Be(5, "both hosts counted into the one row");
        await LiftLockoutAsync(hostA, email);
        var correct = await CorrectCodeAsync(hostA, email);
        (await VerifyAsync(hostB, token, correct)).Succeeded.Should().BeFalse("the sixth attempt is refused on host B, even with the right code");
        (await VerifyAsync(hostA, token, correct)).Succeeded.Should().BeFalse("and on host A");
        (await CountAsync(mode, $"SELECT count FROM {Table(TenantA)}")).Should().BeGreaterThan(5, "the store was consulted and refused");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task FourWrongCodesSplitAcrossTwoHosts_ShouldStillAllowTheCorrectCodeOnEitherHost(TenantSchemaMode mode)
    {
        var keys = NewKeyDirectory();
        await using var hostA = await StartHostAsync(mode, keys);
        await using var hostB = await StartHostAsync(mode, keys);
        var email = await NewTwoFactorUserAsync(hostA);
        var token = await hostA.LoginForTwoFactorTokenAsync(email, TenantA);
        foreach (var host in new[] { hostA, hostB, hostA, hostB })
        {
            (await VerifyAsync(host, token, "000000")).Succeeded.Should().BeFalse();
        }

        var result = await VerifyAsync(hostB, token, await CorrectCodeAsync(hostA, email));

        result.Succeeded.Should().BeTrue("the limit is five attempts, and this is the fifth");
        (await CountAsync(mode, $"SELECT count FROM {Table(TenantA)}")).Should().Be(5);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task TwoFactorToken_ShouldFailOnAnotherHost_WhenTheHostsDoNotShareDataProtectionKeys(TenantSchemaMode mode)
    {
        await using var hostA = await StartHostAsync(mode, NewKeyDirectory());
        await using var hostB = await StartHostAsync(mode, NewKeyDirectory());
        var email = await NewTwoFactorUserAsync(hostA);
        var token = await hostA.LoginForTwoFactorTokenAsync(email, TenantA);
        var code = await CorrectCodeAsync(hostA, email);

        var onB = await VerifyAsync(hostB, token, code);
        (await CountAsync(mode, $"SELECT count(*) FROM {Table(TenantA)}")).Should().Be(0, "host B could not read the token, so it never reached the store");
        var onA = await VerifyAsync(hostA, token, code);

        onB.Succeeded.Should().BeFalse("host B cannot unprotect a token protected with host A's keys");
        onA.Succeeded.Should().BeTrue("the same token and code are good on the host that issued it");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task AddPinotechrdEfTwoFactorAttemptStore_ShouldReplaceTheInMemoryStore(TenantSchemaMode mode)
    {
        await using var api = await StartHostAsync(mode, NewKeyDirectory());

        using var scope = api.Host.Services.CreateScope();

        scope.ServiceProvider.GetRequiredService<ITwoFactorAttemptStore>().Should().BeOfType<EfTwoFactorAttemptStore<SecDb>>();
        scope.ServiceProvider.GetServices<ITwoFactorAttemptStore>().Should().ContainSingle("the InMemory registration is replaced, not added to");
    }
}
