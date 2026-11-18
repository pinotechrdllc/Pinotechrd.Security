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
}
