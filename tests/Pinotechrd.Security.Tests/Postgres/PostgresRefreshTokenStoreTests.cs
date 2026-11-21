using System.Net;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Core;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using NSubstitute;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// The persistent refresh token store (<c>EfRefreshTokenStore</c>) on a real PostgreSQL, in both schema modes. The contract cases are the
/// ones of <c>InMemoryRefreshTokenStoreTests</c>; the rest prove what only a shared database can: restart, several hosts, one atomic UPDATE,
/// hashed storage and tenant-schema-only tables. Each test uses its own token values and users, so tests of a class do not interfere.
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresRefreshTokenStoreTests(PostgresFixture postgres) : IAsyncLifetime
{
    private const string TenantA = "a";
    private const string TenantB = "b";
    private const string Email = "alice@a.test";

    private readonly Dictionary<TenantSchemaMode, string> _databases = [];
    private readonly List<SecDb> _contexts = [];

    public async Task InitializeAsync()
    {
        foreach (var mode in PgProvisioning.Modes)
        {
            var cs = await postgres.CreateDatabaseAsync();
            await PgProvisioning.ProvisionAsync(cs, mode, MapTokens, TenantA, TenantB);
            _databases[mode] = cs;
        }
    }

    public async Task DisposeAsync()
    {
        foreach (var context in _contexts) await context.DisposeAsync();
    }

    public static IEnumerable<object[]> Modes() => PgProvisioning.BothModes();

    private static void MapTokens(PinotechrdSecurityModelOptions o) => o.MapRefreshTokens = true;

    private static string NewToken() => "tok-" + Guid.NewGuid().ToString("N");

    private static string Schema(string tenant) => TenantIdentifier.ToSchemaName(tenant);

    private static DateTime In(TimeSpan span) => DateTime.UtcNow.Add(span);

    private SecDb Db(TenantSchemaMode mode, string tenant)
    {
        var db = PgProvisioning.NewContext(_databases[mode], mode, tenant, MapTokens);
        _contexts.Add(db);
        return db;
    }

    private EfRefreshTokenStore<SecDb> Store(TenantSchemaMode mode, string tenant = TenantA, TimeProvider? time = null) =>
        new(Db(mode, tenant), time);

    private async Task<long> CountAsync(TenantSchemaMode mode, string sql) =>
        Convert.ToInt64(await PgProvisioning.ScalarAsync(_databases[mode], sql));

    // ---- Contract parity with InMemoryRefreshTokenStore --------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task RotateAsync_ShouldStoreIntoALiveFamily_AndRefuseEveryOther(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var (first, revokedFirst) = (NewToken(), NewToken());
        await store.SaveAsync("rot-user", TenantA, first, In(TimeSpan.FromMinutes(10)));
        await store.SaveAsync("rot-revoked", TenantA, revokedFirst, In(TimeSpan.FromMinutes(10)));
        var family = (await store.ConsumeAsync(first, TenantA)).FamilyId!;
        var revokedFamily = (await store.ConsumeAsync(revokedFirst, TenantA)).FamilyId!;
        await store.RevokeAllForUserAsync("rot-revoked");

        var next = NewToken();
        (await store.RotateAsync(family, "rot-user", TenantA, next, In(TimeSpan.FromMinutes(10)))).Should().BeTrue();
        (await store.ConsumeAsync(next, TenantA)).FamilyId.Should().Be(family);

        var refused = NewToken();
        (await store.RotateAsync("never-issued", "rot-user", TenantA, refused, In(TimeSpan.FromMinutes(10)))).Should().BeFalse();
        (await store.RotateAsync(family, "someone-else", TenantA, refused, In(TimeSpan.FromMinutes(10)))).Should().BeFalse();
        (await store.RotateAsync(revokedFamily, "rot-revoked", TenantA, refused, In(TimeSpan.FromMinutes(10)))).Should().BeFalse();
        (await store.ValidateAsync(refused)).IsValid.Should().BeFalse("a refused rotation stores nothing");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task RotateAsync_ShouldRefuse_AFamilyWhoseTokensHaveAllExpired(TenantSchemaMode mode)
    {
        var start = DateTimeOffset.UtcNow;
        var time = new Pinotechrd.Security.Tests.Core.FakeTimeProvider(start);
        var store = Store(mode, time: time);
        var first = NewToken();
        await store.SaveAsync("rot-expired", TenantA, first, start.UtcDateTime.AddMinutes(10));
        var family = (await store.ConsumeAsync(first, TenantA)).FamilyId!;
        time.Advance(TimeSpan.FromMinutes(11));

        (await store.RotateAsync(family, "rot-expired", TenantA, NewToken(), time.GetUtcNow().UtcDateTime.AddMinutes(10))).Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ValidateAsync_ShouldReturnContext_WhenTokenIsValid(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var token = NewToken();
        await store.SaveAsync("user-1", TenantA, token, In(TimeSpan.FromMinutes(10)));

        var result = await store.ValidateAsync(token);

        result.IsValid.Should().BeTrue();
        result.UserId.Should().Be("user-1");
        result.TenantId.Should().Be(TenantA);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ValidateAsync_ShouldFail_WhenTokenIsUnknown(TenantSchemaMode mode)
    {
        var result = await Store(mode).ValidateAsync(NewToken());

        result.IsValid.Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ValidateAsync_ShouldFail_WhenTokenWasRevoked(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var token = NewToken();
        await store.SaveAsync("user-1", TenantA, token, In(TimeSpan.FromMinutes(10)));
        await store.RevokeAsync(token);

        var result = await store.ValidateAsync(token);

        result.IsValid.Should().BeFalse();
        result.Reason.Should().Be("Refresh token revoked");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ValidateAsync_ShouldFail_WhenTokenIsExpired(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var token = NewToken();
        await store.SaveAsync("user-1", TenantA, token, In(TimeSpan.FromMinutes(-1)));

        var result = await store.ValidateAsync(token);

        result.IsValid.Should().BeFalse();
        result.Reason.Should().Be("Refresh token expired");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ValidateAsync_ShouldNotConsumeTheToken(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var token = NewToken();
        await store.SaveAsync("user-1", TenantA, token, In(TimeSpan.FromMinutes(10)));

        (await store.ValidateAsync(token)).IsValid.Should().BeTrue();
        (await store.ValidateAsync(token)).IsValid.Should().BeTrue();

        (await store.ConsumeAsync(token, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ValidateAsync_ShouldFail_WhenTokenWasAlreadyConsumed(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var token = NewToken();
        await store.SaveAsync("user-1", TenantA, token, In(TimeSpan.FromMinutes(10)));
        await store.ConsumeAsync(token, TenantA);

        (await store.ValidateAsync(token)).IsValid.Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAsync_ShouldReturnTheSavedContext_WhenTokenIsValid(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var token = NewToken();
        await store.SaveAsync("user-1", TenantA, token, In(TimeSpan.FromMinutes(10)), "family-1", "stamp-1");

        var result = await store.ConsumeAsync(token, TenantA);

        result.Succeeded.Should().BeTrue();
        result.UserId.Should().Be("user-1");
        result.TenantId.Should().Be(TenantA);
        result.FamilyId.Should().Be("family-1");
        result.SecurityStamp.Should().Be("stamp-1");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAsync_ShouldAssignAFamilyAndReturnNoStamp_WhenNoneIsGiven(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var token = NewToken();
        await store.SaveAsync("user-1", TenantA, token, In(TimeSpan.FromMinutes(10)));

        var result = await store.ConsumeAsync(token, TenantA);

        result.Succeeded.Should().BeTrue();
        result.FamilyId.Should().NotBeNullOrEmpty();
        result.SecurityStamp.Should().BeNull();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAsync_ShouldReturnNotFound_WhenTokenIsUnknown(TenantSchemaMode mode)
    {
        var result = await Store(mode).ConsumeAsync(NewToken(), TenantA);

        result.Status.Should().Be(RefreshTokenConsumeStatus.NotFound);
        result.UserId.Should().BeNull();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAsync_ShouldReturnRevoked_WhenTokenWasRevoked(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var token = NewToken();
        await store.SaveAsync("user-1", TenantA, token, In(TimeSpan.FromMinutes(10)));
        await store.RevokeAsync(token);

        (await store.ConsumeAsync(token, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAsync_ShouldReturnExpired_AtTheExpiryInstant_AndNotConsume(TenantSchemaMode mode)
    {
        var time = new FakeTimeProvider();
        var store = Store(mode, time: time);
        var token = NewToken();
        await store.SaveAsync("user-1", TenantA, token, time.GetUtcNow().UtcDateTime.AddMinutes(10));

        time.Advance(TimeSpan.FromMinutes(10) - TimeSpan.FromSeconds(1));
        var before = await store.ValidateAsync(token);
        time.Advance(TimeSpan.FromSeconds(1));
        var result = await store.ConsumeAsync(token, TenantA);

        before.IsValid.Should().BeTrue();
        result.Status.Should().Be(RefreshTokenConsumeStatus.Expired);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAsync_ShouldConsume_WhenTheInjectedClockIsBeforeExpiry_EvenIfTheRealClockIsAfter(TenantSchemaMode mode)
    {
        // Expiry is decided by the store's injected clock: the real clock is years past 2020.
        var time = new FakeTimeProvider(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var store = Store(mode, time: time);
        var token = NewToken();
        await store.SaveAsync("user-1", TenantA, token, new DateTime(2020, 1, 1, 0, 5, 0, DateTimeKind.Utc));

        (await store.ConsumeAsync(token, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAsync_ShouldReturnReusedAndRevokeTheWholeFamily_WhenTokenIsConsumedTwice(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var (a, b, c, other) = (NewToken(), NewToken(), NewToken(), NewToken());
        var family = Guid.NewGuid().ToString("N");
        var expires = In(TimeSpan.FromMinutes(10));
        await store.SaveAsync("user-1", TenantA, a, expires, family);
        await store.SaveAsync("user-1", TenantA, b, expires, family);
        await store.SaveAsync("user-1", TenantA, other, expires, "other-" + family);

        (await store.ConsumeAsync(a, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
        var reused = await store.ConsumeAsync(a, TenantA);
        reused.Status.Should().Be(RefreshTokenConsumeStatus.Reused);
        reused.Succeeded.Should().BeFalse();
        // Attributed, so the reuse can be logged against its user and family (security event 4204).
        (reused.UserId, reused.TenantId, reused.FamilyId).Should().Be(("user-1", TenantA, family));
        reused.SecurityStamp.Should().BeNull();
        await store.SaveAsync("user-1", TenantA, c, expires, family);

        (await store.ConsumeAsync(b, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
        (await store.ConsumeAsync(c, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
        (await store.ValidateAsync(b)).IsValid.Should().BeFalse();
        (await store.ConsumeAsync(other, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAsync_ShouldReturnReusedAndRevokeTheFamily_WhenTheConsumedTokenAlsoExpired(TenantSchemaMode mode)
    {
        var time = new FakeTimeProvider();
        var store = Store(mode, time: time);
        var (old, sibling) = (NewToken(), NewToken());
        var family = Guid.NewGuid().ToString("N");
        var now = time.GetUtcNow().UtcDateTime;
        await store.SaveAsync("user-1", TenantA, old, now.AddMinutes(5), family);
        await store.SaveAsync("user-1", TenantA, sibling, now.AddHours(1), family);
        (await store.ConsumeAsync(old, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
        time.Advance(TimeSpan.FromMinutes(10));

        (await store.ConsumeAsync(old, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Reused);

        (await store.ConsumeAsync(sibling, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAsync_ShouldReturnReusedAndRevokeTheFamily_WhenTheConsumedTokenWasAlsoRevoked(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var (old, sibling) = (NewToken(), NewToken());
        var family = Guid.NewGuid().ToString("N");
        var expires = In(TimeSpan.FromMinutes(10));
        await store.SaveAsync("user-1", TenantA, old, expires, family);
        await store.SaveAsync("user-1", TenantA, sibling, expires, family);
        await store.ConsumeAsync(old, TenantA);
        await store.RevokeAsync(old);

        (await store.ConsumeAsync(old, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Reused);

        (await store.ConsumeAsync(sibling, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAsync_ShouldNeverConsumeATokenSavedIntoAFamilyRevokedByReuse(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var (a, late) = (NewToken(), NewToken());
        var family = Guid.NewGuid().ToString("N");
        var expires = In(TimeSpan.FromMinutes(10));
        await store.SaveAsync("user-1", TenantA, a, expires, family);
        await store.ConsumeAsync(a, TenantA);
        await store.ConsumeAsync(a, TenantA); // reuse revokes the family

        await store.SaveAsync("user-1", TenantA, late, expires.AddHours(1), family);

        (await store.ConsumeAsync(late, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
        (await store.ValidateAsync(late)).IsValid.Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task SignOutCurrentUserAsync_ShouldRevokeOnlyTheCurrentUsersRowsInTheTenantSchema(TenantSchemaMode mode)
    {
        var provider = NSubstitute.Substitute.For<ISecurityDataProvider>();
        var kit = new AuthManagerTestKit<SignOutUser>(tenant: TenantA, refreshStore: Store(mode), dataProvider: provider);
        kit.TokenProvider.GenerateRefreshToken().Returns(_ => NewToken());
        var a = kit.AddUser("a-" + Guid.NewGuid().ToString("N")[..8] + "@a.test");
        var b = kit.AddUser("b-" + Guid.NewGuid().ToString("N")[..8] + "@a.test");
        var loginA1 = await kit.Manager.LoginAsync(a.Email!, AuthManagerTestKit<SignOutUser>.Password, TenantA);
        var loginA2 = await kit.Manager.LoginAsync(a.Email!, AuthManagerTestKit<SignOutUser>.Password, TenantA);
        var loginB = await kit.Manager.LoginAsync(b.Email!, AuthManagerTestKit<SignOutUser>.Password, TenantA);
        var otherTenant = NewToken();
        await Store(mode, TenantB).SaveAsync(a.Id.ToString(), TenantB, otherTenant, In(TimeSpan.FromMinutes(10)));
        provider.GetCurrentUserId().Returns(a.Id.ToString());

        var signedOut = await kit.Manager.SignOutCurrentUserAsync();

        signedOut.Should().BeTrue();
        var verify = Store(mode);
        (await verify.ValidateAsync(loginA1.Token!.RefreshToken)).IsValid.Should().BeFalse();
        (await verify.ValidateAsync(loginA2.Token!.RefreshToken)).IsValid.Should().BeFalse();
        (await verify.ValidateAsync(loginB.Token!.RefreshToken)).IsValid.Should().BeTrue("another user of the tenant keeps its sessions");
        (await Store(mode, TenantB).ValidateAsync(otherTenant)).IsValid.Should().BeTrue("the revocation reaches the current tenant only");
        (await kit.Manager.RefreshAsync(loginA1.Token.RefreshToken)).Succeeded.Should().BeFalse();
        (await kit.Manager.RefreshAsync(loginB.Token.RefreshToken)).Succeeded.Should().BeTrue();
    }

    public sealed class SignOutUser : BaseSecurityUser;

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAsync_ShouldNeverConsumeATokenSavedIntoAFamilyRevokedBySignOut(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var (first, raced) = (NewToken(), NewToken());
        var family = Guid.NewGuid().ToString("N");
        var user = "user-" + family;
        var expires = In(TimeSpan.FromMinutes(10));
        await store.SaveAsync(user, TenantA, first, expires, family);
        await store.RevokeAllForUserAsync(user);

        await store.SaveAsync(user, TenantA, raced, expires, family);

        (await store.ConsumeAsync(raced, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAsync_ShouldReturnTenantMismatchWithoutConsuming_WhenTheTokenBelongsToAnotherTenantInTheSameSchema(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var token = NewToken();
        await store.SaveAsync("user-1", "tenant-x", token, In(TimeSpan.FromMinutes(10)));

        var mismatch = await store.ConsumeAsync(token, TenantA);
        var owner = await store.ConsumeAsync(token, "tenant-x");

        mismatch.Status.Should().Be(RefreshTokenConsumeStatus.TenantMismatch);
        mismatch.UserId.Should().BeNull();
        mismatch.TenantId.Should().BeNull();
        owner.Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAsync_ShouldChangeNothing_WhenTheTenantDiffers_EvenForAConsumedToken(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var (a, b) = (NewToken(), NewToken());
        var family = Guid.NewGuid().ToString("N");
        var expires = In(TimeSpan.FromMinutes(10));
        await store.SaveAsync("user-1", TenantA, a, expires, family);
        await store.SaveAsync("user-1", TenantA, b, expires, family);
        await store.ConsumeAsync(a, TenantA);

        (await store.ConsumeAsync(a, "tenant-x")).Status.Should().Be(RefreshTokenConsumeStatus.TenantMismatch);

        (await store.ConsumeAsync(b, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Consumed, "a mismatch must not revoke the family");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAsync_ShouldReturnNotFoundAndNotConsume_WhenTheTokenBelongsToAnotherTenantSchema(TenantSchemaMode mode)
    {
        var token = NewToken();
        await Store(mode, TenantB).SaveAsync("user-1", TenantB, token, In(TimeSpan.FromMinutes(10)));

        var fromA = await Store(mode, TenantA).ConsumeAsync(token, TenantB);
        var fromB = await Store(mode, TenantB).ConsumeAsync(token, TenantB);

        fromA.Status.Should().Be(RefreshTokenConsumeStatus.NotFound, "tenant a's schema does not contain the token");
        fromB.Status.Should().Be(RefreshTokenConsumeStatus.Consumed, "the attempt through another schema must not burn the token");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task SaveAsync_ShouldThrowInvalidOperation_WhenTheSameTokenIsSavedTwice(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var token = NewToken();
        await store.SaveAsync("user-1", TenantA, token, In(TimeSpan.FromMinutes(10)));

        var act = () => store.SaveAsync("user-2", TenantA, token, In(TimeSpan.FromMinutes(10)));

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task SaveAsync_ShouldKeepTheFirstTokenState_WhenTheSameValueIsSavedAgain(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var token = NewToken();
        var family = Guid.NewGuid().ToString("N");
        var expires = In(TimeSpan.FromMinutes(10));
        await store.SaveAsync("user-1", TenantA, token, expires, family);
        (await store.ConsumeAsync(token, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);

        var act = () => store.SaveAsync("user-2", TenantA, token, expires, family);
        await act.Should().ThrowAsync<InvalidOperationException>();

        (await store.ConsumeAsync(token, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Reused, "the attempt did not reset the consumed state");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task SaveAsync_ShouldKeepTheFirstOwner_WhenAnotherUserSavesTheSameValue(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var token = NewToken();
        await store.SaveAsync("user-1", TenantA, token, In(TimeSpan.FromMinutes(10)));

        try { await store.SaveAsync("user-2", TenantA, token, In(TimeSpan.FromMinutes(10))); } catch (InvalidOperationException) { }

        (await store.ConsumeAsync(token, TenantA)).UserId.Should().Be("user-1");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task RevokeAsync_ShouldNotThrow_WhenTheTokenIsUnknown(TenantSchemaMode mode)
    {
        var act = () => Store(mode).RevokeAsync(NewToken());

        await act.Should().NotThrowAsync();
    }

    // ---- RevokeAllForUserAsync ---------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task RevokeAllForUserAsync_ShouldRevokeEveryTokenOfThatUserAndNobodyElse(TenantSchemaMode mode)
    {
        var store = Store(mode);
        var suffix = Guid.NewGuid().ToString("N");
        var (user1, user2) = ("user-1-" + suffix, "user-2-" + suffix);
        var (u1a, u1b, u1c, u2a) = (NewToken(), NewToken(), NewToken(), NewToken());
        var expires = In(TimeSpan.FromMinutes(10));
        await store.SaveAsync(user1, TenantA, u1a, expires);
        await store.SaveAsync(user1, TenantA, u1b, expires, "fam-" + suffix);
        await store.SaveAsync(user1, TenantA, u1c, expires, "fam-" + suffix);
        await store.SaveAsync(user2, TenantA, u2a, expires);

        await store.RevokeAllForUserAsync(user1);

        (await store.ConsumeAsync(u1a, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
        (await store.ConsumeAsync(u1b, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
        (await store.ConsumeAsync(u1c, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
        (await store.ConsumeAsync(u2a, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task RevokeAllForUserAsync_ShouldNotTouchTheTokensOfAnotherTenantSchema(TenantSchemaMode mode)
    {
        var user = "user-" + Guid.NewGuid().ToString("N");
        var (inA, inB) = (NewToken(), NewToken());
        await Store(mode, TenantA).SaveAsync(user, TenantA, inA, In(TimeSpan.FromMinutes(10)));
        await Store(mode, TenantB).SaveAsync(user, TenantB, inB, In(TimeSpan.FromMinutes(10)));

        await Store(mode, TenantA).RevokeAllForUserAsync(user);

        (await Store(mode, TenantA).ConsumeAsync(inA, TenantA)).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
        (await Store(mode, TenantB).ConsumeAsync(inB, TenantB)).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task RevokeAllForUserAsync_ShouldNotThrow_WhenTheUserHasNoTokens(TenantSchemaMode mode)
    {
        var act = () => Store(mode).RevokeAllForUserAsync("nobody-" + Guid.NewGuid().ToString("N"));

        await act.Should().NotThrowAsync();
    }

    // ---- Concurrency -------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAsync_ShouldSucceedForExactlyOneCaller_When32ContextsConsumeTheSameToken(TenantSchemaMode mode)
    {
        for (var trial = 0; trial < 3; trial++)
        {
            var token = NewToken();
            await Store(mode).SaveAsync("user-1", TenantA, token, In(TimeSpan.FromMinutes(10)), Guid.NewGuid().ToString("N"));
            var stores = Enumerable.Range(0, 32).Select(_ => Store(mode)).ToArray();
            using var gate = new ManualResetEventSlim(false);

            var tasks = stores.Select(store => Task.Run(async () =>
            {
                gate.Wait();
                return await store.ConsumeAsync(token, TenantA);
            })).ToArray();
            gate.Set();
            var results = await Task.WhenAll(tasks);

            results.Count(r => r.Status == RefreshTokenConsumeStatus.Consumed).Should().Be(1, $"trial {trial}: a refresh token is single use");
            // A loser is a reuse (consumed token) or, when another loser already revoked the family, revoked; never anything else.
            var losers = results.Where(r => r.Status != RefreshTokenConsumeStatus.Consumed).ToArray();
            losers.Should().HaveCount(31);
            losers.Should().OnlyContain(r => r.Status == RefreshTokenConsumeStatus.Reused || r.Status == RefreshTokenConsumeStatus.Revoked, $"trial {trial}");
            losers.Should().Contain(r => r.Status == RefreshTokenConsumeStatus.Reused, $"trial {trial}: the first loser to look sees a reuse");
            (await Store(mode).ValidateAsync(token)).IsValid.Should().BeFalse();
        }
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Refresh_ShouldSucceedForExactlyOneClient_When32ClientsRefreshTheSameTokenOverHttp(TenantSchemaMode mode)
    {
        await using var api = await StartHostAsync(mode, withUser: true);
        var (_, refresh) = await api.LoginAsync(Email, TenantA);

        var statuses = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(async () =>
            (await api.PostAsync("/api/auth/refresh", new RefreshRequest(refresh), TenantA)).StatusCode)));

        statuses.Count(s => s == HttpStatusCode.OK).Should().Be(1);
        statuses.Count(s => s == HttpStatusCode.Unauthorized).Should().Be(31);
    }

    // ---- Restart and several hosts -----------------------------------------------------------

    private async Task<TenantDatabaseApi> StartHostAsync(TenantSchemaMode mode, bool withUser) =>
        await TenantDatabaseApi.StartAsync(
            new Dictionary<string, string[]> { [TenantA] = withUser ? [Email] : [] },
            mode,
            configureOptions: options => options.UsePinotechrdSecurity(o =>
            {
                o.TenantSchemaMode = mode;
                o.MapRefreshTokens = true;
            }),
            useDatabase: (options, _) => options.UseNpgsql(_databases[mode]),
            provision: false,
            configureBuilder: builder => builder.Services.AddPinotechrdEfRefreshTokenStore<SecDb>());

    private static async Task<(HttpStatusCode Status, string? Refresh)> RefreshAsync(TenantDatabaseApi api, string refresh)
    {
        var response = await api.PostAsync("/api/auth/refresh", new RefreshRequest(refresh), TenantA);
        if (response.StatusCode != HttpStatusCode.OK) return (response.StatusCode, null);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return (response.StatusCode, json.RootElement.GetProperty("refresh").GetString());
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Refresh_ShouldSucceedOnANewHostInstance_WhenTheTokenWasIssuedBeforeARestart(TenantSchemaMode mode)
    {
        string refresh;
        await using (var hostA = await StartHostAsync(mode, withUser: true))
        {
            (_, refresh) = await hostA.LoginAsync(Email, TenantA);
        }

        await using var restarted = await StartHostAsync(mode, withUser: false);
        var (status, next) = await RefreshAsync(restarted, refresh);

        status.Should().Be(HttpStatusCode.OK);
        next.Should().NotBeNullOrEmpty().And.NotBe(refresh);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Refresh_ShouldRevokeTheFamily_WhenAnOldTokenIsReplayedOnAnotherHostOfTheSameDatabase(TenantSchemaMode mode)
    {
        await using var hostA = await StartHostAsync(mode, withUser: true);
        await using var hostB = await StartHostAsync(mode, withUser: false);
        var (_, first) = await hostA.LoginAsync(Email, TenantA);

        var (rotated, second) = await RefreshAsync(hostA, first);
        var (replay, _) = await RefreshAsync(hostB, first);
        var (afterReplayOnA, _) = await RefreshAsync(hostA, second!);
        var (afterReplayOnB, _) = await RefreshAsync(hostB, second!);

        rotated.Should().Be(HttpStatusCode.OK);
        replay.Should().Be(HttpStatusCode.Unauthorized);
        afterReplayOnA.Should().Be(HttpStatusCode.Unauthorized, "the replay on B revoked the family the new token belongs to");
        afterReplayOnB.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Refresh_ShouldBeRefusedWithoutConsumingTheToken_WhileTheUserIsLockedOut(TenantSchemaMode mode)
    {
        await using var api = await StartHostAsync(mode, withUser: true);
        var (_, refresh) = await api.LoginAsync(Email, TenantA);

        Task<bool> SetLockoutAsync(DateTimeOffset? end) => api.InTenantAsync(TenantA, async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            return (await users.SetLockoutEndDateAsync((await users.FindByEmailAsync(Email))!, end)).Succeeded;
        });

        (await SetLockoutAsync(DateTimeOffset.UtcNow.AddMinutes(10))).Should().BeTrue();
        var (locked, _) = await RefreshAsync(api, refresh);
        var stillValid = await api.InTenantAsync(TenantA, async sp => (await sp.GetRequiredService<IRefreshTokenStore>().ValidateAsync(refresh)).IsValid);

        (await SetLockoutAsync(null)).Should().BeTrue();
        var (afterLockout, next) = await RefreshAsync(api, refresh);

        locked.Should().Be(HttpStatusCode.Unauthorized);
        stillValid.Should().BeTrue("the refused refresh left the token unconsumed");
        afterLockout.Should().Be(HttpStatusCode.OK, "the session survived the lockout");
        next.Should().NotBe(refresh);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task AddPinotechrdEfRefreshTokenStore_ShouldReplaceTheInMemoryStore(TenantSchemaMode mode)
    {
        await using var api = await StartHostAsync(mode, withUser: false);

        using var scope = api.Host.Services.CreateScope();

        scope.ServiceProvider.GetRequiredService<IRefreshTokenStore>().Should().BeOfType<EfRefreshTokenStore<SecDb>>();
        scope.ServiceProvider.GetServices<IRefreshTokenStore>().Should().ContainSingle("the InMemory registration is replaced, not added to");
    }

    // ---- Storage -----------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Database_ShouldKeepOnlyTheSha256OfEachToken_AsA32ByteKey(TenantSchemaMode mode)
    {
        var token = "plain-" + Guid.NewGuid().ToString("N");
        await Store(mode).SaveAsync("user-1", TenantA, token, In(TimeSpan.FromMinutes(10)));
        var table = $"\"{Schema(TenantA)}\".refresh_tokens";

        var wrongLength = await CountAsync(mode, $"SELECT count(*) FROM {table} WHERE octet_length(token_hash) <> 32");
        var hashed = await CountAsync(mode, $"SELECT count(*) FROM {table} WHERE token_hash = sha256(convert_to('{token}', 'UTF8'))");

        wrongLength.Should().Be(0);
        hashed.Should().Be(1, "the primary key is the SHA-256 of the UTF-8 token");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Database_ShouldNotContainTheTokenValueInAnyColumnOfEitherTable(TenantSchemaMode mode)
    {
        var token = "plain-" + Guid.NewGuid().ToString("N");
        var family = "fam-" + Guid.NewGuid().ToString("N");
        await Store(mode).SaveAsync("user-1", TenantA, token, In(TimeSpan.FromMinutes(10)), family);
        await Store(mode).ConsumeAsync(token, TenantA);
        await Store(mode).ConsumeAsync(token, TenantA); // reuse writes the families table too

        var inTokens = await CountAsync(mode, $"SELECT count(*) FROM \"{Schema(TenantA)}\".refresh_tokens t WHERE t::text LIKE '%{token}%'");
        var rowsOfFamily = await CountAsync(mode, $"SELECT count(*) FROM \"{Schema(TenantA)}\".refresh_tokens WHERE family_id = '{family}'");
        var inFamilies = await CountAsync(mode, $"SELECT count(*) FROM \"{Schema(TenantA)}\".refresh_token_families f WHERE f::text LIKE '%{token}%'");
        var revokedFamilies = await CountAsync(mode, $"SELECT count(*) FROM \"{Schema(TenantA)}\".refresh_token_families WHERE family_id = '{family}' AND revoked_at IS NOT NULL");

        inTokens.Should().Be(0);
        inFamilies.Should().Be(0);
        rowsOfFamily.Should().Be(1, "the token was stored");
        revokedFamilies.Should().Be(1, "the reuse was recorded");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Tables_ShouldExistInEveryTenantSchemaOnly_NeverInTheCatalogSchema(TenantSchemaMode mode)
    {
        foreach (var table in new[] { "refresh_tokens", "refresh_token_families" })
        {
            await using var connection = new NpgsqlConnection(_databases[mode]);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $"SELECT table_schema FROM information_schema.tables WHERE table_name = '{table}' ORDER BY 1";
            var schemas = new List<string>();
            await using (var reader = await command.ExecuteReaderAsync())
            {
                while (await reader.ReadAsync()) schemas.Add(reader.GetString(0));
            }

            schemas.Should().BeEquivalentTo([Schema(TenantA), Schema(TenantB)], table);
            schemas.Should().NotContain("public");
        }
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Tokens_ShouldBeStoredInTheTenantSchemaOfTheContextOnly(TenantSchemaMode mode)
    {
        var token = NewToken();
        await Store(mode, TenantA).SaveAsync("user-1", TenantA, token, In(TimeSpan.FromMinutes(10)));

        var inA = await CountAsync(mode, $"SELECT count(*) FROM \"{Schema(TenantA)}\".refresh_tokens WHERE token_hash = sha256(convert_to('{token}', 'UTF8'))");
        var inB = await CountAsync(mode, $"SELECT count(*) FROM \"{Schema(TenantB)}\".refresh_tokens WHERE token_hash = sha256(convert_to('{token}', 'UTF8'))");

        inA.Should().Be(1);
        inB.Should().Be(0);
    }

    // ---- Shared context ----------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task SaveAsync_ShouldNotFlushOtherTrackedChangesOfTheSharedContext(TenantSchemaMode mode)
    {
        var db = Db(mode, TenantA);
        var store = new EfRefreshTokenStore<SecDb>(db);
        var code = "PENDING" + Guid.NewGuid().ToString("N")[..8].ToUpperInvariant();
        var pending = new SecurityModule { Id = SecurityModuleId.FromCode(code), Code = code, Name = "Pending", TenantId = TenantA };
        db.SecurityModules.Add(pending);
        var token = NewToken();

        await store.SaveAsync("user-1", TenantA, token, In(TimeSpan.FromMinutes(10)));

        db.Entry(pending).State.Should().Be(EntityState.Added, "the store must neither save nor discard the application's pending changes");
        var other = Db(mode, TenantA);
        (await other.SecurityModules.AnyAsync(m => m.Code == code)).Should().BeFalse("the pending entity was never written");
        (await store.ValidateAsync(token)).IsValid.Should().BeTrue("the token itself was written");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ConsumeAndRevoke_ShouldNotFlushOtherTrackedChangesOfTheSharedContext(TenantSchemaMode mode)
    {
        var db = Db(mode, TenantA);
        var store = new EfRefreshTokenStore<SecDb>(db);
        var token = NewToken();
        var user = "user-" + Guid.NewGuid().ToString("N");
        await store.SaveAsync(user, TenantA, token, In(TimeSpan.FromMinutes(10)));
        var code = "PENDING" + Guid.NewGuid().ToString("N")[..8].ToUpperInvariant();
        var pending = new SecurityModule { Id = SecurityModuleId.FromCode(code), Code = code, Name = "Pending", TenantId = TenantA };
        db.SecurityModules.Add(pending);

        await store.ConsumeAsync(token, TenantA);
        await store.ConsumeAsync(token, TenantA); // reuse
        await store.RevokeAsync(token);
        await store.RevokeAllForUserAsync(user);

        db.Entry(pending).State.Should().Be(EntityState.Added);
        (await Db(mode, TenantA).SecurityModules.AnyAsync(m => m.Code == code)).Should().BeFalse();
    }

    // ---- Flag off ----------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task EveryStoreMethod_ShouldThrowInvalidOperationMentioningMapRefreshTokens_WhenTheModelDoesNotMapTheTables(TenantSchemaMode mode)
    {
        await using var db = PgProvisioning.NewContext(_databases[mode], mode, TenantA);
        var store = new EfRefreshTokenStore<SecDb>(db);
        var expires = In(TimeSpan.FromMinutes(10));

        var calls = new Func<Task>[]
        {
            () => store.SaveAsync("user-1", TenantA, "t", expires),
            () => store.ValidateAsync("t"),
            () => store.ConsumeAsync("t", TenantA),
            () => store.RevokeAsync("t"),
            () => store.RevokeAllForUserAsync("user-1")
        };

        foreach (var call in calls)
        {
            await call.Should().ThrowAsync<InvalidOperationException>().WithMessage("*MapRefreshTokens*");
        }
    }
}
