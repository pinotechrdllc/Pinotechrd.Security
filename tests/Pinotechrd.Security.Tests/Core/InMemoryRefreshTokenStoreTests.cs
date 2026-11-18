using FluentAssertions;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Interfaces;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

public class InMemoryRefreshTokenStoreTests
{
    [Fact]
    public async Task ValidateAsync_ShouldReturnContext_WhenTokenIsValid()
    {
        var store = new InMemoryRefreshTokenStore();
        var token = "refresh-token-valid";

        await store.SaveAsync("user-1", "tenant-a", token, DateTime.UtcNow.AddMinutes(10));

        var result = await store.ValidateAsync(token);

        result.IsValid.Should().BeTrue();
        result.UserId.Should().Be("user-1");
        result.TenantId.Should().Be("tenant-a");
    }

    [Fact]
    public async Task ValidateAsync_ShouldFail_WhenTokenWasRevoked()
    {
        var store = new InMemoryRefreshTokenStore();
        var token = "refresh-token-revoked";

        await store.SaveAsync("user-1", "tenant-a", token, DateTime.UtcNow.AddMinutes(10));
        await store.RevokeAsync(token);

        var result = await store.ValidateAsync(token);

        result.IsValid.Should().BeFalse();
        result.Reason.Should().Be("Refresh token revoked");
    }

    [Fact]
    public async Task ValidateAsync_ShouldFail_WhenTokenIsExpired()
    {
        var store = new InMemoryRefreshTokenStore();
        var token = "refresh-token-expired";

        await store.SaveAsync("user-1", "tenant-a", token, DateTime.UtcNow.AddMinutes(-1));

        var result = await store.ValidateAsync(token);

        result.IsValid.Should().BeFalse();
        result.Reason.Should().Be("Refresh token expired");
    }

    [Fact]
    public async Task ValidateAsync_ShouldNotConsumeTheToken()
    {
        var store = new InMemoryRefreshTokenStore();
        await store.SaveAsync("user-1", "tenant-a", "t1", DateTime.UtcNow.AddMinutes(10));

        (await store.ValidateAsync("t1")).IsValid.Should().BeTrue();
        (await store.ValidateAsync("t1")).IsValid.Should().BeTrue();
        var consumed = await store.ConsumeAsync("t1", "tenant-a");

        consumed.Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
    }

    [Fact]
    public async Task ValidateAsync_ShouldFail_WhenTokenWasAlreadyConsumed()
    {
        var store = new InMemoryRefreshTokenStore();
        await store.SaveAsync("user-1", "tenant-a", "t1", DateTime.UtcNow.AddMinutes(10));
        await store.ConsumeAsync("t1", "tenant-a");

        (await store.ValidateAsync("t1")).IsValid.Should().BeFalse();
    }

    // ---- ConsumeAsync ------------------------------------------------------------------------

    [Fact]
    public async Task ConsumeAsync_ShouldReturnTheSavedContext_WhenTokenIsValid()
    {
        var store = new InMemoryRefreshTokenStore();
        await store.SaveAsync("user-1", "tenant-a", "t1", DateTime.UtcNow.AddMinutes(10), "family-1", "stamp-1");

        var result = await store.ConsumeAsync("t1", "tenant-a");

        result.Succeeded.Should().BeTrue();
        result.UserId.Should().Be("user-1");
        result.TenantId.Should().Be("tenant-a");
        result.FamilyId.Should().Be("family-1");
        result.SecurityStamp.Should().Be("stamp-1");
    }

    [Fact]
    public async Task ConsumeAsync_ShouldAssignAFamily_WhenNoneIsGiven()
    {
        var store = new InMemoryRefreshTokenStore();
        await store.SaveAsync("user-1", "tenant-a", "t1", DateTime.UtcNow.AddMinutes(10));

        var result = await store.ConsumeAsync("t1", "tenant-a");

        result.FamilyId.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task ConsumeAsync_ShouldReturnNotFound_WhenTokenIsUnknown()
    {
        var store = new InMemoryRefreshTokenStore();

        var result = await store.ConsumeAsync("unknown", "tenant-a");

        result.Status.Should().Be(RefreshTokenConsumeStatus.NotFound);
        result.UserId.Should().BeNull();
    }

    [Fact]
    public async Task ConsumeAsync_ShouldReturnExactlyOneConsumed_WhenTwoConsumesRace()
    {
        for (var trial = 0; trial < 100; trial++)
        {
            var store = new InMemoryRefreshTokenStore();
            await store.SaveAsync("user-1", "tenant-a", "t1", DateTime.UtcNow.AddMinutes(10), "family-1");
            using var gate = new ManualResetEventSlim(false);

            var tasks = Enumerable.Range(0, 2).Select(_ => Task.Run(async () =>
            {
                gate.Wait();
                return await store.ConsumeAsync("t1", "tenant-a");
            })).ToArray();
            gate.Set();
            var results = await Task.WhenAll(tasks);

            results.Count(r => r.Status == RefreshTokenConsumeStatus.Consumed)
                .Should().Be(1, $"trial {trial}: a refresh token is single use");
        }
    }

    [Fact]
    public async Task ConsumeAsync_ShouldReturnReusedAndRevokeTheWholeFamily_WhenTokenIsConsumedTwice()
    {
        var store = new InMemoryRefreshTokenStore();
        var expires = DateTime.UtcNow.AddMinutes(10);
        await store.SaveAsync("user-1", "tenant-a", "a", expires, "family-1");
        await store.SaveAsync("user-1", "tenant-a", "b", expires, "family-1");
        await store.SaveAsync("user-1", "tenant-a", "other-family", expires, "family-2");

        (await store.ConsumeAsync("a", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
        (await store.ConsumeAsync("a", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Reused);
        // A token saved after the reuse is born revoked.
        await store.SaveAsync("user-1", "tenant-a", "c", expires, "family-1");

        (await store.ConsumeAsync("b", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
        (await store.ConsumeAsync("c", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
        (await store.ValidateAsync("b")).IsValid.Should().BeFalse();
        (await store.ConsumeAsync("other-family", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
    }

    [Fact]
    public async Task ConsumeAsync_ShouldReturnTenantMismatchWithoutConsuming_WhenTenantDiffers()
    {
        var store = new InMemoryRefreshTokenStore();
        await store.SaveAsync("user-1", "tenant-a", "t1", DateTime.UtcNow.AddMinutes(10));

        (await store.ConsumeAsync("t1", "tenant-b")).Status.Should().Be(RefreshTokenConsumeStatus.TenantMismatch);
        (await store.ConsumeAsync("t1", "TENANT-A")).Status.Should().Be(RefreshTokenConsumeStatus.TenantMismatch);
        (await store.ConsumeAsync("t1", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
    }

    [Fact]
    public async Task ConsumeAsync_ShouldReturnTenantMismatchWithoutLeakingTheOwner()
    {
        var store = new InMemoryRefreshTokenStore();
        await store.SaveAsync("user-1", "tenant-a", "t1", DateTime.UtcNow.AddMinutes(10));

        var result = await store.ConsumeAsync("t1", "tenant-b");

        result.UserId.Should().BeNull();
        result.TenantId.Should().BeNull();
    }

    [Fact]
    public async Task ConsumeAsync_ShouldReturnExpired_AtTheExpiryInstant_AndNotConsume()
    {
        var time = new FakeTimeProvider();
        var store = new InMemoryRefreshTokenStore(time);
        await store.SaveAsync("user-1", "tenant-a", "t1", time.GetUtcNow().UtcDateTime.AddMinutes(10));

        time.Advance(TimeSpan.FromMinutes(10) - TimeSpan.FromSeconds(1));
        var before = await store.ValidateAsync("t1");
        time.Advance(TimeSpan.FromSeconds(1));
        var result = await store.ConsumeAsync("t1", "tenant-a");

        before.IsValid.Should().BeTrue();
        result.Status.Should().Be(RefreshTokenConsumeStatus.Expired);
    }

    [Fact]
    public async Task ConsumeAsync_ShouldReturnRevoked_WhenTokenWasRevoked()
    {
        var store = new InMemoryRefreshTokenStore();
        await store.SaveAsync("user-1", "tenant-a", "t1", DateTime.UtcNow.AddMinutes(10));
        await store.RevokeAsync("t1");

        (await store.ConsumeAsync("t1", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
    }

    // ---- RevokeAllForUserAsync ---------------------------------------------------------------

    [Fact]
    public async Task RevokeAllForUserAsync_ShouldRevokeEveryTokenOfThatUserAndNobodyElse()
    {
        var store = new InMemoryRefreshTokenStore();
        var expires = DateTime.UtcNow.AddMinutes(10);
        await store.SaveAsync("user-1", "tenant-a", "u1-a", expires);
        await store.SaveAsync("user-1", "tenant-b", "u1-b", expires);
        await store.SaveAsync("user-2", "tenant-a", "u2-a", expires);

        await store.RevokeAllForUserAsync("user-1");

        (await store.ConsumeAsync("u1-a", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
        (await store.ConsumeAsync("u1-b", "tenant-b")).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
        (await store.ConsumeAsync("u2-a", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
    }

    [Fact]
    public async Task RevokeAllForUserAsync_ShouldAlsoRevokeATokenSavedLaterIntoTheSameFamily()
    {
        var store = new InMemoryRefreshTokenStore();
        var expires = DateTime.UtcNow.AddMinutes(10);
        await store.SaveAsync("user-1", "tenant-a", "first", expires, "family-1");

        await store.RevokeAllForUserAsync("user-1");
        await store.SaveAsync("user-1", "tenant-a", "late", expires, "family-1");

        (await store.ConsumeAsync("late", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
    }

    [Fact]
    public async Task RevokeAllForUserAsync_ShouldNotThrow_WhenTheUserHasNoTokens()
    {
        var store = new InMemoryRefreshTokenStore();

        var act = () => store.RevokeAllForUserAsync("nobody");

        await act.Should().NotThrowAsync();
    }

    // ---- Duplicate tokens --------------------------------------------------------------------

    [Fact]
    public async Task SaveAsync_ShouldThrow_WhenTheSameTokenIsSavedTwice()
    {
        var store = new InMemoryRefreshTokenStore();
        await store.SaveAsync("user-1", "tenant-a", "t1", DateTime.UtcNow.AddMinutes(10));

        var act = () => store.SaveAsync("user-2", "tenant-b", "t1", DateTime.UtcNow.AddMinutes(10));

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task SaveAsync_ShouldKeepTheFirstTokenConsumed_WhenTheSameValueIsSavedAgain()
    {
        var store = new InMemoryRefreshTokenStore();
        var expires = DateTime.UtcNow.AddMinutes(10);
        await store.SaveAsync("user-1", "tenant-a", "t1", expires, "family-1");
        (await store.ConsumeAsync("t1", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);

        var act = () => store.SaveAsync("user-1", "tenant-a", "t1", expires, "family-1");
        await act.Should().ThrowAsync<InvalidOperationException>();

        // The attempt did not reset the state: the token is still consumed, so presenting it again is a reuse.
        (await store.ConsumeAsync("t1", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Reused);
    }

    [Fact]
    public async Task SaveAsync_ShouldKeepTheFirstTokenOwner_WhenAnotherUserSavesTheSameValue()
    {
        var store = new InMemoryRefreshTokenStore();
        await store.SaveAsync("user-1", "tenant-a", "t1", DateTime.UtcNow.AddMinutes(10));

        try { await store.SaveAsync("user-2", "tenant-b", "t1", DateTime.UtcNow.AddMinutes(10)); } catch (InvalidOperationException) { }

        var result = await store.ConsumeAsync("t1", "tenant-a");
        result.UserId.Should().Be("user-1");
    }

    // ---- Reuse wins over expiry and revocation of the token itself ---------------------------

    [Fact]
    public async Task ConsumeAsync_ShouldReturnReusedAndRevokeTheFamily_WhenTheConsumedTokenAlsoExpired()
    {
        var time = new FakeTimeProvider();
        var store = new InMemoryRefreshTokenStore(time);
        var now = time.GetUtcNow().UtcDateTime;
        await store.SaveAsync("user-1", "tenant-a", "old", now.AddMinutes(5), "family-1");
        await store.SaveAsync("user-1", "tenant-a", "sibling", now.AddHours(1), "family-1");
        (await store.ConsumeAsync("old", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
        time.Advance(TimeSpan.FromMinutes(10));

        (await store.ConsumeAsync("old", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Reused);

        (await store.ConsumeAsync("sibling", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
    }

    [Fact]
    public async Task ConsumeAsync_ShouldReturnReusedAndRevokeTheFamily_WhenTheConsumedTokenWasAlsoRevoked()
    {
        var store = new InMemoryRefreshTokenStore();
        var expires = DateTime.UtcNow.AddMinutes(10);
        await store.SaveAsync("user-1", "tenant-a", "old", expires, "family-1");
        await store.SaveAsync("user-1", "tenant-a", "sibling", expires, "family-1");
        await store.ConsumeAsync("old", "tenant-a");
        await store.RevokeAsync("old");

        (await store.ConsumeAsync("old", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Reused);

        (await store.ConsumeAsync("sibling", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
    }

    [Fact]
    public async Task ConsumeAsync_ShouldNeverConsumeATokenSavedIntoARevokedFamily()
    {
        var store = new InMemoryRefreshTokenStore();
        var expires = DateTime.UtcNow.AddMinutes(10);
        await store.SaveAsync("user-1", "tenant-a", "a", expires, "family-1");
        await store.ConsumeAsync("a", "tenant-a");
        await store.ConsumeAsync("a", "tenant-a"); // reuse revokes family-1

        await store.SaveAsync("user-1", "tenant-a", "late", expires.AddHours(1), "family-1");

        (await store.ConsumeAsync("late", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
        (await store.ValidateAsync("late")).IsValid.Should().BeFalse();
    }

    [Fact]
    public async Task ConsumeAsync_ShouldNeverConsumeATokenSavedIntoAFamilyRevokedBySignOut()
    {
        var store = new InMemoryRefreshTokenStore();
        var expires = DateTime.UtcNow.AddMinutes(10);
        await store.SaveAsync("user-1", "tenant-a", "a", expires, "family-1");
        await store.RevokeAllForUserAsync("user-1");

        await store.SaveAsync("user-1", "tenant-a", "raced", expires, "family-1");

        (await store.ConsumeAsync("raced", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
    }

    // ---- Documented precedence for every pair of conditions ---------------------------------

    // Order from the README: unknown token, tenant mismatch, family revoked, reused, revoked, expired.
    private enum Condition { TenantMismatch, FamilyRevoked, Consumed, Revoked, Expired }

    private static RefreshTokenConsumeStatus ExpectedFor(IReadOnlyCollection<Condition> conditions)
    {
        if (conditions.Contains(Condition.TenantMismatch)) return RefreshTokenConsumeStatus.TenantMismatch;
        if (conditions.Contains(Condition.FamilyRevoked)) return RefreshTokenConsumeStatus.Revoked;
        if (conditions.Contains(Condition.Consumed)) return RefreshTokenConsumeStatus.Reused;
        if (conditions.Contains(Condition.Revoked)) return RefreshTokenConsumeStatus.Revoked;
        if (conditions.Contains(Condition.Expired)) return RefreshTokenConsumeStatus.Expired;
        return RefreshTokenConsumeStatus.Consumed;
    }

    public static TheoryData<string> Combinations()
    {
        var all = Enum.GetValues<Condition>();
        var data = new TheoryData<string>();
        data.Add(string.Empty);
        foreach (var single in all) data.Add(single.ToString());
        for (var i = 0; i < all.Length; i++)
        {
            for (var j = i + 1; j < all.Length; j++) data.Add($"{all[i]},{all[j]}");
        }
        data.Add(string.Join(",", all));
        return data;
    }

    [Theory]
    [MemberData(nameof(Combinations))]
    public async Task ConsumeAsync_ShouldFollowTheDocumentedPrecedence(string combination)
    {
        var conditions = combination.Length == 0
            ? new HashSet<Condition>()
            : combination.Split(',').Select(Enum.Parse<Condition>).ToHashSet();
        var time = new FakeTimeProvider();
        var store = new InMemoryRefreshTokenStore(time);
        var expires = time.GetUtcNow().UtcDateTime.AddMinutes(5);
        await store.SaveAsync("user-1", "tenant-a", "t1", expires, "family-1");

        // Order matters: consume first (a revoked family cannot be consumed), then revoke, then let the clock run.
        if (conditions.Contains(Condition.Consumed)) await store.ConsumeAsync("t1", "tenant-a");
        if (conditions.Contains(Condition.Revoked)) await store.RevokeAsync("t1");
        if (conditions.Contains(Condition.FamilyRevoked)) await store.RevokeAllForUserAsync("user-1");
        if (conditions.Contains(Condition.Expired)) time.Advance(TimeSpan.FromMinutes(10));
        var tenant = conditions.Contains(Condition.TenantMismatch) ? "tenant-b" : "tenant-a";

        var result = await store.ConsumeAsync("t1", tenant);

        result.Status.Should().Be(ExpectedFor(conditions), $"conditions: [{combination}]");
    }

    [Fact]
    public async Task ConsumeAsync_ShouldReturnNotFound_EvenWhenTheTenantIsWrong_ForAnUnknownToken()
    {
        var store = new InMemoryRefreshTokenStore();

        (await store.ConsumeAsync("nope", "tenant-z")).Status.Should().Be(RefreshTokenConsumeStatus.NotFound);
    }

    [Fact]
    public async Task ConsumeAsync_ShouldChangeNothing_WhenTheTenantDiffers_EvenForAConsumedToken()
    {
        var store = new InMemoryRefreshTokenStore();
        var expires = DateTime.UtcNow.AddMinutes(10);
        await store.SaveAsync("user-1", "tenant-a", "a", expires, "family-1");
        await store.SaveAsync("user-1", "tenant-a", "b", expires, "family-1");
        await store.ConsumeAsync("a", "tenant-a");

        (await store.ConsumeAsync("a", "tenant-b")).Status.Should().Be(RefreshTokenConsumeStatus.TenantMismatch);

        // A mismatch must not revoke the family: the sibling is still good.
        (await store.ConsumeAsync("b", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
    }

    // ---- Purging above the threshold ---------------------------------------------------------

    // The threshold adapts to the size of the store, so the tests keep adding live tokens until the probe token is dropped
    // (or fail if that takes more than a few times the documented 10,000 entries).
    private static async Task PushLiveTokensUntilDropped(InMemoryRefreshTokenStore store, string probe, DateTime liveUntil)
    {
        for (var chunk = 0; chunk < 70; chunk++)
        {
            for (var i = 0; i < 1_000; i++)
            {
                var n = chunk * 1_000 + i;
                await store.SaveAsync("filler-user", "tenant-a", $"live-{n}", liveUntil, $"live-family-{n}");
            }

            if ((await store.ValidateAsync(probe)).Reason == "Refresh token not found") return;
        }

        throw new Xunit.Sdk.XunitException($"The expired token {probe} was never dropped after 70,000 saves.");
    }

    [Fact]
    public async Task SaveAsync_ShouldDropExpiredTokensAndKeepLiveOnes_WhenTheStoreGrowsAboveItsThreshold()
    {
        var time = new FakeTimeProvider();
        var store = new InMemoryRefreshTokenStore(time);
        var now = time.GetUtcNow().UtcDateTime;
        await store.SaveAsync("user-1", "tenant-a", "live", now.AddHours(2), "live-family");
        await store.SaveAsync("user-1", "tenant-a", "short", now.AddMinutes(1), "short-family");
        time.Advance(TimeSpan.FromMinutes(5));

        await PushLiveTokensUntilDropped(store, "short", now.AddHours(10));

        (await store.ConsumeAsync("short", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.NotFound, "an expired token is dropped");
        (await store.ConsumeAsync("live", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
        (await store.ConsumeAsync("live-3", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
    }

    [Fact]
    public async Task SaveAsync_ShouldNotDropAnything_WhileTheStoreIsBelowItsThreshold()
    {
        var time = new FakeTimeProvider();
        var store = new InMemoryRefreshTokenStore(time);
        var now = time.GetUtcNow().UtcDateTime;
        await store.SaveAsync("user-1", "tenant-a", "short", now.AddMinutes(1), "short-family");

        time.Advance(TimeSpan.FromMinutes(5));
        await store.SaveAsync("user-1", "tenant-a", "other", now.AddHours(1), "other-family");

        (await store.ConsumeAsync("short", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Expired);
    }

    [Fact]
    public async Task SaveAsync_ShouldRememberARevokedFamilyUntilItsLatestTokenExpires()
    {
        var time = new FakeTimeProvider();
        var store = new InMemoryRefreshTokenStore(time);
        var now = time.GetUtcNow().UtcDateTime;
        await store.SaveAsync("user-1", "tenant-a", "a", now.AddMinutes(10), "family-1");
        await store.SaveAsync("user-1", "tenant-a", "b", now.AddMinutes(30), "family-1");
        await store.SaveAsync("user-2", "tenant-a", "probe", now.AddMinutes(5), "probe-family");
        await store.ConsumeAsync("a", "tenant-a");
        await store.ConsumeAsync("a", "tenant-a"); // reuse: family-1 is revoked and remembered until b would expire (+30 min)
        time.Advance(TimeSpan.FromMinutes(15));    // a and the probe have expired, b has not

        await PushLiveTokensUntilDropped(store, "probe", now.AddHours(10));
        await store.SaveAsync("user-1", "tenant-a", "late", now.AddHours(5), "family-1");

        (await store.ConsumeAsync("late", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Revoked,
            "the family is remembered until its latest token expiry");
    }

    [Fact]
    public async Task SaveAsync_ShouldForgetARevokedFamily_OnceItsLatestTokenHasExpiredAndTheStoreIsPurged()
    {
        var time = new FakeTimeProvider();
        var store = new InMemoryRefreshTokenStore(time);
        var now = time.GetUtcNow().UtcDateTime;
        await store.SaveAsync("user-1", "tenant-a", "a", now.AddMinutes(10), "family-1");
        await store.SaveAsync("user-2", "tenant-a", "probe", now.AddMinutes(5), "probe-family");
        await store.ConsumeAsync("a", "tenant-a");
        await store.ConsumeAsync("a", "tenant-a"); // family-1 revoked, remembered until +10 min
        time.Advance(TimeSpan.FromMinutes(20));

        await PushLiveTokensUntilDropped(store, "probe", now.AddHours(10));
        await store.SaveAsync("user-1", "tenant-a", "reborn", now.AddHours(5), "family-1");

        (await store.ConsumeAsync("reborn", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Consumed,
            "an expired revoked family is dropped to bound memory");
    }

    // ---- A consumed token is kept until its whole family expired ------------------------------

    [Fact]
    public async Task ReplayOfAConsumedToken_ShouldGiveReusedAndRevokeTheFamily_EvenAfterAPurge_WhileTheFamilyIsLive()
    {
        var time = new FakeTimeProvider();
        var store = new InMemoryRefreshTokenStore(time);
        var now = time.GetUtcNow().UtcDateTime;
        await store.SaveAsync("user-1", "tenant-a", "old", now.AddMinutes(10), "family-1");
        await store.SaveAsync("user-1", "tenant-a", "current", now.AddHours(1), "family-1");
        await store.SaveAsync("user-2", "tenant-a", "probe", now.AddMinutes(5), "probe-family");
        (await store.ConsumeAsync("old", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Consumed);
        time.Advance(TimeSpan.FromMinutes(20)); // old and the probe have expired, the family has not

        await PushLiveTokensUntilDropped(store, "probe", now.AddHours(10));

        (await store.ConsumeAsync("old", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Reused);
        (await store.ConsumeAsync("current", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.Revoked);
    }

    [Fact]
    public async Task ConsumedTokens_ShouldBePurged_OnceTheWholeFamilyHasExpired()
    {
        var time = new FakeTimeProvider();
        var store = new InMemoryRefreshTokenStore(time);
        var now = time.GetUtcNow().UtcDateTime;
        await store.SaveAsync("user-1", "tenant-a", "old", now.AddMinutes(10), "family-1");
        await store.SaveAsync("user-1", "tenant-a", "current", now.AddMinutes(30), "family-1");
        await store.ConsumeAsync("old", "tenant-a");
        time.Advance(TimeSpan.FromMinutes(45)); // the whole family has expired

        await PushLiveTokensUntilDropped(store, "old", now.AddHours(10));

        (await store.ConsumeAsync("old", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.NotFound);
        (await store.ConsumeAsync("current", "tenant-a")).Status.Should().Be(RefreshTokenConsumeStatus.NotFound);
    }
}
