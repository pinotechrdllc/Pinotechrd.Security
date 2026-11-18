using FluentAssertions;
using Pinotechrd.Security.Core;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

public class InMemoryTwoFactorAttemptStoreTests
{
    [Fact]
    public async Task RegisterAttemptAsync_ShouldCountPerChallenge()
    {
        var store = new InMemoryTwoFactorAttemptStore();
        var expires = DateTimeOffset.UtcNow.AddMinutes(5);

        (await store.RegisterAttemptAsync("a", expires)).Should().Be(1);
        (await store.RegisterAttemptAsync("a", expires)).Should().Be(2);
        (await store.RegisterAttemptAsync("b", expires)).Should().Be(1);
        (await store.RegisterAttemptAsync("a", expires)).Should().Be(3);
    }

    [Fact]
    public async Task RegisterAttemptAsync_ShouldHandOutEachCountOnce_WhenCalledConcurrently()
    {
        var store = new InMemoryTwoFactorAttemptStore();
        var expires = DateTimeOffset.UtcNow.AddMinutes(5);

        var counts = await Task.WhenAll(Enumerable.Range(0, 200)
            .Select(_ => Task.Run(() => store.RegisterAttemptAsync("shared", expires))));

        counts.OrderBy(c => c).Should().Equal(Enumerable.Range(1, 200));
    }

    [Fact]
    public async Task RegisterAttemptAsync_ShouldKeepCountingBeforeExpiry()
    {
        var time = new FakeTimeProvider();
        var store = new InMemoryTwoFactorAttemptStore(time);
        var expires = time.GetUtcNow().AddMinutes(5);
        await store.RegisterAttemptAsync("a", expires);

        time.Advance(TimeSpan.FromMinutes(4));

        (await store.RegisterAttemptAsync("a", expires)).Should().Be(2);
    }

    // The store bounds its memory by dropping expired challenges once it holds a large number of them,
    // so "forgetting" is observable only after that purge runs.
    [Fact]
    public async Task RegisterAttemptAsync_ShouldForgetExpiredChallenges_AndKeepLiveOnes_WhenThePurgeRuns()
    {
        var time = new FakeTimeProvider();
        var store = new InMemoryTwoFactorAttemptStore(time);
        var shortLived = time.GetUtcNow().AddMinutes(1);
        var longLived = time.GetUtcNow().AddHours(1);
        await store.RegisterAttemptAsync("expired", shortLived);
        await store.RegisterAttemptAsync("expired", shortLived);
        await store.RegisterAttemptAsync("live", longLived);
        for (var i = 0; i < 10_100; i++) await store.RegisterAttemptAsync($"filler-{i}", shortLived);

        time.Advance(TimeSpan.FromMinutes(2));
        await store.RegisterAttemptAsync("trigger", longLived);

        (await store.RegisterAttemptAsync("expired", longLived)).Should().Be(1);
        (await store.RegisterAttemptAsync("live", longLived)).Should().Be(2);
    }

    [Fact]
    public async Task RegisterAttemptAsync_ShouldReturnIntMaxValue_AfterTheChallengeIsExhausted()
    {
        var store = new InMemoryTwoFactorAttemptStore();
        var expires = DateTimeOffset.UtcNow.AddMinutes(5);
        await store.RegisterAttemptAsync("a", expires);

        await store.ExhaustAsync("a", expires);

        (await store.RegisterAttemptAsync("a", expires)).Should().Be(int.MaxValue);
        (await store.RegisterAttemptAsync("a", expires)).Should().Be(int.MaxValue);
    }

    [Fact]
    public async Task ExhaustAsync_ShouldSpendAChallengeThatHasNeverBeenUsed_AndNotTouchOthers()
    {
        var store = new InMemoryTwoFactorAttemptStore();
        var expires = DateTimeOffset.UtcNow.AddMinutes(5);

        await store.ExhaustAsync("spent", expires);

        (await store.RegisterAttemptAsync("spent", expires)).Should().Be(int.MaxValue);
        (await store.RegisterAttemptAsync("other", expires)).Should().Be(1);
    }

    [Fact]
    public async Task ExhaustAsync_ShouldSpendTheChallengeEvenWhenCalledConcurrentlyWithAttempts()
    {
        var store = new InMemoryTwoFactorAttemptStore();
        var expires = DateTimeOffset.UtcNow.AddMinutes(5);

        await Task.WhenAll(Enumerable.Range(0, 50).Select(i => Task.Run(async () =>
        {
            if (i == 25) await store.ExhaustAsync("a", expires);
            else await store.RegisterAttemptAsync("a", expires);
        })));

        (await store.RegisterAttemptAsync("a", expires)).Should().Be(int.MaxValue);
    }
}
