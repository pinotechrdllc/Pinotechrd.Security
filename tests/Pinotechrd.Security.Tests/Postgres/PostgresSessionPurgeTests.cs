using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Core;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// <c>IPinotechrdSessionPurger</c> on a real PostgreSQL, in both schema modes: what it deletes, what it must keep so that
/// replay detection and two-factor attempt counts survive, and that it only touches the current tenant's schema.
/// Each test has its own databases and a fake clock.
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresSessionPurgeTests(PostgresFixture postgres) : IAsyncLifetime
{
    private const string TenantA = "a";
    private const string TenantB = "b";

    private readonly Dictionary<TenantSchemaMode, string> _databases = [];
    private readonly List<SecDb> _contexts = [];
    private readonly FakeTimeProvider _time = new();

    public async Task InitializeAsync()
    {
        foreach (var mode in PgProvisioning.Modes)
        {
            var cs = await postgres.CreateDatabaseAsync();
            await PgProvisioning.ProvisionAsync(cs, mode, MapBoth, TenantA, TenantB);
            _databases[mode] = cs;
        }
    }

    public async Task DisposeAsync()
    {
        foreach (var context in _contexts) await context.DisposeAsync();
    }

    public static IEnumerable<object[]> Modes() => PgProvisioning.BothModes();

    private static void MapBoth(PinotechrdSecurityModelOptions o)
    {
        o.MapRefreshTokens = true;
        o.MapTwoFactorAttempts = true;
    }

    private static void MapTokensOnly(PinotechrdSecurityModelOptions o) => o.MapRefreshTokens = true;

    private static void MapAttemptsOnly(PinotechrdSecurityModelOptions o) => o.MapTwoFactorAttempts = true;

    private static string NewToken() => "tok-" + Guid.NewGuid().ToString("N");

    private static string NewFamily() => Guid.NewGuid().ToString("N");

    private static string Schema(string tenant) => TenantIdentifier.ToSchemaName(tenant);

    private DateTime Now => _time.GetUtcNow().UtcDateTime;

    private SecDb Db(TenantSchemaMode mode, string tenant, Action<PinotechrdSecurityModelOptions>? configure = null)
    {
        var db = PgProvisioning.NewContext(_databases[mode], mode, tenant, configure ?? MapBoth);
        _contexts.Add(db);
        return db;
    }

    private EfSessionPurger<SecDb> Purger(TenantSchemaMode mode, string tenant = TenantA, Action<PinotechrdSecurityModelOptions>? configure = null) =>
        new(Db(mode, tenant, configure), _time);

    private EfRefreshTokenStore<SecDb> Tokens(TenantSchemaMode mode, string tenant = TenantA) => new(Db(mode, tenant), _time);

    private EfTwoFactorAttemptStore<SecDb> Attempts(TenantSchemaMode mode, string tenant = TenantA) => new(Db(mode, tenant));

    private async Task<long> CountAsync(TenantSchemaMode mode, string tenant, string table) =>
        Convert.ToInt64(await PgProvisioning.ScalarAsync(_databases[mode], $"SELECT count(*) FROM \"{Schema(tenant)}\".{table}"));

    private Task<long> TokenRows(TenantSchemaMode mode, string tenant = TenantA) => CountAsync(mode, tenant, "refresh_tokens");

    private Task<long> FamilyRows(TenantSchemaMode mode, string tenant = TenantA) => CountAsync(mode, tenant, "refresh_token_families");

    private Task<long> AttemptRows(TenantSchemaMode mode, string tenant = TenantA) => CountAsync(mode, tenant, "two_factor_attempts");

    private Task InsertOrphanFamilyAsync(TenantSchemaMode mode, string family, string tenant = TenantA) =>
        PgProvisioning.ExecuteAsync(_databases[mode], $"INSERT INTO \"{Schema(tenant)}\".refresh_token_families (family_id, revoked_at) VALUES ('{family}', now())");

    // ---- Refresh tokens ----------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldDeleteAFullyExpiredFamilyWithItsConsumedToken_AndCountTheRows(TenantSchemaMode mode)
    {
        var store = Tokens(mode);
        var (old, successor, bystander) = (NewToken(), NewToken(), NewToken());
        var family = NewFamily();
        await store.SaveAsync("user-1", TenantA, old, Now.AddMinutes(10), family);
        await store.SaveAsync("user-1", TenantA, successor, Now.AddMinutes(20), family);
        await store.SaveAsync("user-2", TenantA, bystander, Now.AddDays(1));
        (await store.ConsumeAsync(old, TenantA)).Succeeded.Should().BeTrue();
        await store.RevokeAllForUserAsync("user-1"); // gives the family a revoked row
        _time.Advance(TimeSpan.FromHours(3));

        var result = await Purger(mode).PurgeExpiredAsync();

        result.Should().Be(new SessionPurgeResult(RefreshTokens: 2, RefreshTokenFamilies: 1, TwoFactorAttempts: 0));
        (await TokenRows(mode)).Should().Be(1, "only the live bystander token remains");
        (await FamilyRows(mode)).Should().Be(0);
        (await Tokens(mode).ValidateAsync(bystander)).IsValid.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldKeepEveryTokenOfAFamily_WhenAnyTokenExpiresAfterTheCutoff(TenantSchemaMode mode)
    {
        var store = Tokens(mode);
        var (expired, live) = (NewToken(), NewToken());
        var family = NewFamily();
        await store.SaveAsync("user-1", TenantA, expired, Now.AddMinutes(10), family);
        await store.SaveAsync("user-1", TenantA, live, Now.AddHours(10), family);
        _time.Advance(TimeSpan.FromHours(3));

        var result = await Purger(mode).PurgeExpiredAsync();

        result.Should().Be(new SessionPurgeResult(0, 0, 0));
        (await TokenRows(mode)).Should().Be(2);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldKeepReplayDetection_ForAConsumedTokenOfAFamilyWithALiveToken(TenantSchemaMode mode)
    {
        var store = Tokens(mode);
        var (consumed, live) = (NewToken(), NewToken());
        var family = NewFamily();
        await store.SaveAsync("user-1", TenantA, consumed, Now.AddMinutes(10), family);
        await store.SaveAsync("user-1", TenantA, live, Now.AddHours(10), family);
        (await store.ConsumeAsync(consumed, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
        _time.Advance(TimeSpan.FromHours(3));

        await Purger(mode).PurgeExpiredAsync();

        (await Tokens(mode).ConsumeAsync(consumed, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Reused);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldKeepAFamilyWhoseLastTokenExpiredInsideTheMargin(TenantSchemaMode mode)
    {
        var store = Tokens(mode);
        await store.SaveAsync("user-1", TenantA, NewToken(), Now.AddMinutes(10), NewFamily());
        _time.Advance(TimeSpan.FromMinutes(10) + TimeSpan.FromMinutes(30)); // expired 30 min ago, margin is 1 h

        var result = await Purger(mode).PurgeExpiredAsync();

        result.RefreshTokens.Should().Be(0);
        (await TokenRows(mode)).Should().Be(1);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldDeleteATokenExpiringExactlyAtTheCutoff_AndKeepOneJustAfter(TenantSchemaMode mode)
    {
        var store = Tokens(mode);
        var (atCutoff, afterCutoff) = (NewToken(), NewToken());
        var cutoff = Now.AddMinutes(-5); // the minimum margin
        await store.SaveAsync("user-1", TenantA, atCutoff, cutoff, NewFamily());
        await store.SaveAsync("user-2", TenantA, afterCutoff, cutoff.AddSeconds(1), NewFamily());

        var result = await Purger(mode).PurgeExpiredAsync(IPinotechrdSessionPurger.MinimumMargin);

        result.RefreshTokens.Should().Be(1);
        (await TokenRows(mode)).Should().Be(1);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldKeepARevokedFamilyRow_WhileAnyOfItsTokensRemains(TenantSchemaMode mode)
    {
        var store = Tokens(mode);
        var family = NewFamily();
        await store.SaveAsync("user-1", TenantA, NewToken(), Now.AddMinutes(10), family);
        await store.SaveAsync("user-1", TenantA, NewToken(), Now.AddHours(10), family);
        await store.RevokeAllForUserAsync("user-1");
        (await FamilyRows(mode)).Should().Be(1);
        _time.Advance(TimeSpan.FromHours(3));

        var result = await Purger(mode).PurgeExpiredAsync();

        result.Should().Be(new SessionPurgeResult(0, 0, 0));
        (await FamilyRows(mode)).Should().Be(1, "a revoked family row must outlive a live token of the family");
        (await TokenRows(mode)).Should().Be(2);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldDeleteTheRevokedFamilyRow_OnceNoneOfItsTokensRemains(TenantSchemaMode mode)
    {
        var store = Tokens(mode);
        await store.SaveAsync("user-1", TenantA, NewToken(), Now.AddMinutes(10), NewFamily());
        await store.RevokeAllForUserAsync("user-1");
        (await FamilyRows(mode)).Should().Be(1);
        _time.Advance(TimeSpan.FromHours(3));

        var result = await Purger(mode).PurgeExpiredAsync();

        result.Should().Be(new SessionPurgeResult(1, 1, 0));
        (await FamilyRows(mode)).Should().Be(0);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldDeleteAnOrphanFamilyRow_AndKeepFamiliesThatStillHaveTokens(TenantSchemaMode mode)
    {
        var store = Tokens(mode);
        await store.SaveAsync("user-1", TenantA, NewToken(), Now.AddDays(1), NewFamily());
        await store.RevokeAllForUserAsync("user-1");
        await InsertOrphanFamilyAsync(mode, NewFamily());
        (await FamilyRows(mode)).Should().Be(2);

        var result = await Purger(mode).PurgeExpiredAsync();

        result.Should().Be(new SessionPurgeResult(0, 1, 0));
        (await FamilyRows(mode)).Should().Be(1);
        (await TokenRows(mode)).Should().Be(1);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldBeIdempotent(TenantSchemaMode mode)
    {
        await Tokens(mode).SaveAsync("user-1", TenantA, NewToken(), Now.AddMinutes(1), NewFamily());
        _time.Advance(TimeSpan.FromHours(5));

        var first = await Purger(mode).PurgeExpiredAsync();
        var second = await Purger(mode).PurgeExpiredAsync();

        first.RefreshTokens.Should().Be(1);
        second.Should().Be(new SessionPurgeResult(0, 0, 0));
    }

    // ---- Two-factor attempts -----------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldDeleteOnlyAttemptsOlderThanTheMargin(TenantSchemaMode mode)
    {
        var store = Attempts(mode);
        var now = _time.GetUtcNow();
        await store.RegisterAttemptAsync("old", now.AddHours(-2));
        await store.RegisterAttemptAsync("inside-margin", now.AddMinutes(-30));
        await store.RegisterAttemptAsync("at-cutoff", now.AddHours(-1));
        await store.RegisterAttemptAsync("valid", now.AddMinutes(5));

        var result = await Purger(mode).PurgeExpiredAsync();

        result.Should().Be(new SessionPurgeResult(0, 0, 1));
        (await AttemptRows(mode)).Should().Be(3, "an attempt expiring exactly at the cutoff is kept");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldNotResetTheAttemptCountOfAStillValidToken(TenantSchemaMode mode)
    {
        var store = Attempts(mode);
        var expires = _time.GetUtcNow().AddMinutes(5);
        for (var i = 1; i <= 3; i++) (await store.RegisterAttemptAsync("challenge-1", expires)).Should().Be(i);

        await Purger(mode).PurgeExpiredAsync();

        (await Attempts(mode).RegisterAttemptAsync("challenge-1", expires)).Should().Be(4);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldNotResetTheAttemptCount_OfATokenThatExpiredInsideTheMargin(TenantSchemaMode mode)
    {
        var expires = _time.GetUtcNow().AddMinutes(5);
        await Attempts(mode).RegisterAttemptAsync("challenge-1", expires);
        await Attempts(mode).RegisterAttemptAsync("challenge-1", expires);
        _time.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromMinutes(20));

        await Purger(mode).PurgeExpiredAsync();

        (await Attempts(mode).RegisterAttemptAsync("challenge-1", expires)).Should().Be(3);
    }

    // ---- Margin ------------------------------------------------------------------------------

    [Fact]
    public void DefaultMargin_ShouldBeOneHour() =>
        IPinotechrdSessionPurger.DefaultMargin.Should().Be(TimeSpan.FromHours(1));

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldUseTheDefaultMargin_WhenNoneIsGiven(TenantSchemaMode mode)
    {
        var now = _time.GetUtcNow();
        await Attempts(mode).RegisterAttemptAsync("just-inside", now.AddMinutes(-59));
        await Attempts(mode).RegisterAttemptAsync("just-outside", now.AddMinutes(-61));

        var result = await Purger(mode).PurgeExpiredAsync();

        result.TwoFactorAttempts.Should().Be(1);
        (await AttemptRows(mode)).Should().Be(1);
    }

    [Fact]
    public void MinimumMargin_ShouldBeFiveMinutes() =>
        IPinotechrdSessionPurger.MinimumMargin.Should().Be(TimeSpan.FromMinutes(5));

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldAcceptExactlyTheMinimumMargin_AndDeleteWhatExpiredBeforeNowMinusIt(TenantSchemaMode mode)
    {
        var now = _time.GetUtcNow();
        await Attempts(mode).RegisterAttemptAsync("expired", now.AddMinutes(-5).AddSeconds(-1));
        await Attempts(mode).RegisterAttemptAsync("inside", now.AddMinutes(-4));
        await Tokens(mode).SaveAsync("user-1", TenantA, NewToken(), Now.AddMinutes(-6), NewFamily());
        await Tokens(mode).SaveAsync("user-2", TenantA, NewToken(), Now.AddMinutes(-4), NewFamily());

        var result = await Purger(mode).PurgeExpiredAsync(TimeSpan.FromMinutes(5));

        result.Should().Be(new SessionPurgeResult(1, 0, 1));
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldThrowArgumentOutOfRange_WhenMarginIsZero_OrBelowTheMinimum(TenantSchemaMode mode)
    {
        await Attempts(mode).RegisterAttemptAsync("c", _time.GetUtcNow().AddDays(-1));

        foreach (var margin in new[] { TimeSpan.Zero, TimeSpan.FromMinutes(4) + TimeSpan.FromSeconds(59) })
        {
            var act = () => Purger(mode).PurgeExpiredAsync(margin);

            (await act.Should().ThrowAsync<ArgumentOutOfRangeException>()).Which.ParamName.Should().Be("margin");
        }

        (await AttemptRows(mode)).Should().Be(1);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldHonourAGivenMargin(TenantSchemaMode mode)
    {
        await Attempts(mode).RegisterAttemptAsync("c", _time.GetUtcNow().AddMinutes(-10));

        (await Purger(mode).PurgeExpiredAsync(TimeSpan.FromMinutes(15))).TwoFactorAttempts.Should().Be(0);
        (await Purger(mode).PurgeExpiredAsync(TimeSpan.FromMinutes(5))).TwoFactorAttempts.Should().Be(1);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldThrowArgumentOutOfRange_WhenMarginIsNegative_AndDeleteNothing(TenantSchemaMode mode)
    {
        await Attempts(mode).RegisterAttemptAsync("c", _time.GetUtcNow().AddDays(-1));

        var act = () => Purger(mode).PurgeExpiredAsync(TimeSpan.FromTicks(-1));

        (await act.Should().ThrowAsync<ArgumentOutOfRangeException>()).Which.ParamName.Should().Be("margin");
        (await AttemptRows(mode)).Should().Be(1);
    }

    // ---- Mapping -----------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldThrowNamingBothOptions_WhenNothingIsMapped(TenantSchemaMode mode)
    {
        var act = () => Purger(mode, configure: _ => { }).PurgeExpiredAsync();

        var ex = (await act.Should().ThrowAsync<InvalidOperationException>()).Which;
        ex.Message.Should().Contain("MapRefreshTokens").And.Contain("MapTwoFactorAttempts");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldPurgeOnlyRefreshTokens_WhenOnlyTheyAreMapped(TenantSchemaMode mode)
    {
        await Tokens(mode).SaveAsync("user-1", TenantA, NewToken(), Now.AddMinutes(1), NewFamily());
        await Attempts(mode).RegisterAttemptAsync("c", _time.GetUtcNow().AddDays(-1));
        _time.Advance(TimeSpan.FromHours(5));

        var result = await Purger(mode, configure: MapTokensOnly).PurgeExpiredAsync();

        result.Should().Be(new SessionPurgeResult(1, 0, 0));
        (await AttemptRows(mode)).Should().Be(1, "the attempts table is not mapped, so it is left alone");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldPurgeOnlyAttempts_WhenOnlyTheyAreMapped(TenantSchemaMode mode)
    {
        await Tokens(mode).SaveAsync("user-1", TenantA, NewToken(), Now.AddMinutes(1), NewFamily());
        await Attempts(mode).RegisterAttemptAsync("c", _time.GetUtcNow().AddDays(-1));
        _time.Advance(TimeSpan.FromHours(5));

        var result = await Purger(mode, configure: MapAttemptsOnly).PurgeExpiredAsync();

        result.Should().Be(new SessionPurgeResult(0, 0, 1));
        (await TokenRows(mode)).Should().Be(1, "the refresh token tables are not mapped, so they are left alone");
    }

    // ---- Tenancy -----------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldLeaveAnotherTenantsRowsUntouched(TenantSchemaMode mode)
    {
        foreach (var tenant in new[] { TenantA, TenantB })
        {
            await Tokens(mode, tenant).SaveAsync("user-1", tenant, NewToken(), Now.AddMinutes(1), NewFamily());
            await Tokens(mode, tenant).RevokeAllForUserAsync("user-1");
            await InsertOrphanFamilyAsync(mode, NewFamily(), tenant);
            await Attempts(mode, tenant).RegisterAttemptAsync("c-" + tenant, _time.GetUtcNow().AddMinutes(1));
        }
        _time.Advance(TimeSpan.FromHours(5));

        var result = await Purger(mode, TenantA).PurgeExpiredAsync();

        result.Should().Be(new SessionPurgeResult(1, 2, 1));
        (await TokenRows(mode, TenantA)).Should().Be(0);
        (await FamilyRows(mode, TenantA)).Should().Be(0);
        (await AttemptRows(mode, TenantA)).Should().Be(0);
        (await TokenRows(mode, TenantB)).Should().Be(1);
        (await FamilyRows(mode, TenantB)).Should().Be(2);
        (await AttemptRows(mode, TenantB)).Should().Be(1);
    }

    // ---- The README job ----------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PurgeExpiredAsync_ShouldPurgeTheTenantOfTheScope_WhenResolvedFromTheContainer(TenantSchemaMode mode)
    {
        await Tokens(mode).SaveAsync("user-1", TenantA, NewToken(), Now.AddMinutes(1), NewFamily());
        await Tokens(mode, TenantB).SaveAsync("user-1", TenantB, NewToken(), Now.AddMinutes(1), NewFamily());
        await Attempts(mode).RegisterAttemptAsync("c", _time.GetUtcNow().AddMinutes(1));
        _time.Advance(TimeSpan.FromHours(5));

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(_time);
        services.AddScoped<ISchemaProvider, DbSchemaProvider>();
        services.AddDbContext<SecDb>(options => options.UseNpgsql(_databases[mode]).UsePinotechrdSecurity(model =>
        {
            model.TenantSchemaMode = mode;
            MapBoth(model);
        }));
        services.AddPinotechrdSecurity<SecDb, HostUser, HostRole>(options =>
        {
            options.Jwt.Secret = TenantDatabaseApi.Secret;
            options.Jwt.Issuer = TenantDatabaseApi.Issuer;
            options.Jwt.Audience = TenantDatabaseApi.Audience;
        });
        services.AddPinotechrdEfRefreshTokenStore<SecDb>();
        services.AddPinotechrdEfTwoFactorAttemptStore<SecDb>();
        await using var provider = services.BuildServiceProvider();

        SessionPurgeResult result;
        using (var scope = provider.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantContext>().SetTenant(TenantA);
            result = await scope.ServiceProvider.GetRequiredService<IPinotechrdSessionPurger>().PurgeExpiredAsync();
        }

        result.Should().Be(new SessionPurgeResult(1, 0, 1));
        (await TokenRows(mode, TenantB)).Should().Be(1);
    }
}
