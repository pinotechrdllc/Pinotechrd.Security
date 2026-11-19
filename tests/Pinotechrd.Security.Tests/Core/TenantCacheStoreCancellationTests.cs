using FluentAssertions;
using Microsoft.Extensions.Caching.Distributed;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;
using Xunit;
using MsOptions = Microsoft.Extensions.Options.Options;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>The tenant cache hands the caller's token to every distributed-cache call and to the inner store.</summary>
public class TenantCacheStoreCancellationTests
{
    private readonly ISecurityStore _inner = Substitute.For<ISecurityStore>();
    private readonly RecordingCache _cache = new();

    private TenantCacheStore Store() => new(_inner, _cache,
        MsOptions.Create(new PinotechrdSecurityOptions { TenantCacheExpiration = TimeSpan.FromMinutes(5) }));

    [Fact]
    public async Task IsSubscriptionActiveAsync_ShouldPassTheCallerTokenToEveryCacheCallAndTheInnerStore()
    {
        using var cts = new CancellationTokenSource();
        _inner.IsSubscriptionActiveAsync("tenant-a", Arg.Any<CancellationToken>()).Returns(true);

        await Store().IsSubscriptionActiveAsync("tenant-a", cts.Token);

        _cache.Tokens.Should().NotBeEmpty().And.OnlyContain(t => t == cts.Token);
        _cache.Tokens.Count.Should().BeGreaterThanOrEqualTo(4, "generation get and set, data get and set");
        await _inner.Received(1).IsSubscriptionActiveAsync("tenant-a", cts.Token);
    }

    [Fact]
    public async Task GetActiveModuleCodesAsync_ShouldPassTheCallerTokenToEveryCacheCallAndTheInnerStore()
    {
        using var cts = new CancellationTokenSource();
        _inner.GetActiveModuleCodesAsync("tenant-a", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IEnumerable<string>>(["SALES"]));

        await Store().GetActiveModuleCodesAsync("tenant-a", cts.Token);

        _cache.Tokens.Should().NotBeEmpty().And.OnlyContain(t => t == cts.Token);
        await _inner.Received(1).GetActiveModuleCodesAsync("tenant-a", cts.Token);
    }

    [Fact]
    public async Task InvalidateTenantAsync_ShouldPassTheCallerTokenToTheCache()
    {
        using var cts = new CancellationTokenSource();

        await Store().InvalidateTenantAsync("tenant-a", cts.Token);

        _cache.Tokens.Should().NotBeEmpty().And.OnlyContain(t => t == cts.Token);
    }

    [Fact]
    public async Task IsSubscriptionActiveAsync_ShouldThrowOperationCanceledBeforeTheInnerStore_WhenTheTokenIsAlreadyCancelled()
    {
        var act = () => Store().IsSubscriptionActiveAsync("tenant-a", new CancellationToken(canceled: true));

        await act.Should().ThrowAsync<OperationCanceledException>();
        await _inner.DidNotReceiveWithAnyArgs().IsSubscriptionActiveAsync(default!, default);
    }

    /// <summary>Records the token of each call; like a real cache it throws when the token is already cancelled.</summary>
    private sealed class RecordingCache : IDistributedCache
    {
        private readonly Dictionary<string, byte[]> _data = [];
        public List<CancellationToken> Tokens { get; } = [];

        private void Observe(CancellationToken token)
        {
            Tokens.Add(token);
            token.ThrowIfCancellationRequested();
        }

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default)
        {
            Observe(token);
            return Task.FromResult(_data.TryGetValue(key, out var v) ? v : null);
        }

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            Observe(token);
            _data[key] = value;
            return Task.CompletedTask;
        }

        public Task RefreshAsync(string key, CancellationToken token = default) { Observe(token); return Task.CompletedTask; }

        public Task RemoveAsync(string key, CancellationToken token = default) { Observe(token); _data.Remove(key); return Task.CompletedTask; }

        public byte[]? Get(string key) => throw new NotSupportedException("The store must use the async API.");

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => throw new NotSupportedException();

        public void Refresh(string key) => throw new NotSupportedException();

        public void Remove(string key) => throw new NotSupportedException();
    }
}
