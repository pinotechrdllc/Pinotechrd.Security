using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using MsOptions = Microsoft.Extensions.Options.Options;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;
using Pinotechrd.Security.Options;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>Tenant cache: served from an IDistributedCache, invalidated per tenant, shared across instances.</summary>
public class TenantCacheStoreTests
{
    private const string TenantA = "tenant-a";
    private const string TenantB = "tenant-b";

    private readonly ISecurityStore _inner = Substitute.For<ISecurityStore>();
    private readonly IDistributedCache _cache = new MemoryDistributedCache(MsOptions.Create(new MemoryDistributedCacheOptions()));

    public TenantCacheStoreTests()
    {
        Setup(_inner, active: true, "SALES", "STOCK");
    }

    private static void Setup(ISecurityStore store, bool active, params string[] codes)
    {
        store.IsSubscriptionActiveAsync(Arg.Any<string>()).Returns(active);
        store.GetActiveModuleCodesAsync(Arg.Any<string>()).Returns(_ => Task.FromResult<IEnumerable<string>>(codes));
    }

    private static TenantCacheStore NewStore(ISecurityStore inner, IDistributedCache cache, TimeSpan? expiration = null) =>
        new(inner, cache, MsOptions.Create(new PinotechrdSecurityOptions
        {
            TenantCacheExpiration = expiration ?? TimeSpan.FromMinutes(5)
        }));

    private TenantCacheStore Store(TimeSpan? expiration = null) => NewStore(_inner, _cache, expiration);

    // ---- cached reads ------------------------------------------------------------------------

    [Fact]
    public async Task IsSubscriptionActiveAsync_ShouldCallInnerOnce_WhenReadTwice()
    {
        var store = Store();

        (await store.IsSubscriptionActiveAsync(TenantA)).Should().BeTrue();
        (await store.IsSubscriptionActiveAsync(TenantA)).Should().BeTrue();

        await _inner.Received(1).IsSubscriptionActiveAsync(TenantA);
    }

    [Fact]
    public async Task IsSubscriptionActiveAsync_ShouldCacheAnInactiveAnswer_Too()
    {
        Setup(_inner, active: false);
        var store = Store();

        (await store.IsSubscriptionActiveAsync(TenantA)).Should().BeFalse();
        (await store.IsSubscriptionActiveAsync(TenantA)).Should().BeFalse();

        await _inner.Received(1).IsSubscriptionActiveAsync(TenantA);
    }

    [Fact]
    public async Task GetActiveModuleCodesAsync_ShouldCallInnerOnce_AndReturnTheSameCodes_WhenReadTwice()
    {
        var store = Store();

        var first = await store.GetActiveModuleCodesAsync(TenantA);
        var second = await store.GetActiveModuleCodesAsync(TenantA);

        first.Should().BeEquivalentTo("SALES", "STOCK");
        second.Should().BeEquivalentTo("SALES", "STOCK");
        await _inner.Received(1).GetActiveModuleCodesAsync(TenantA);
    }

    [Fact]
    public async Task GetActiveModuleCodesAsync_ShouldCacheAnEmptyList()
    {
        Setup(_inner, active: true);
        var store = Store();

        (await store.GetActiveModuleCodesAsync(TenantA)).Should().BeEmpty();
        (await store.GetActiveModuleCodesAsync(TenantA)).Should().BeEmpty();

        await _inner.Received(1).GetActiveModuleCodesAsync(TenantA);
    }

    [Theory]
    [InlineData("SALES", true)]
    [InlineData("sales", true)]
    [InlineData(" Sales ", true)]
    [InlineData("OTHER", false)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    public async Task IsModuleActiveAsync_ShouldUseTheCachedCodeSetWithTheCodeNormalized(string code, bool expected)
    {
        var store = Store();

        (await store.IsModuleActiveAsync(TenantA, code)).Should().Be(expected);
        (await store.IsModuleActiveAsync(TenantA, "STOCK")).Should().BeTrue();

        await _inner.DidNotReceiveWithAnyArgs().IsModuleActiveAsync(default!, default!);
        await _inner.Received(1).GetActiveModuleCodesAsync(TenantA);
    }

    [Fact]
    public async Task IsModuleActiveAsync_ShouldReuseTheEntryWrittenByGetActiveModuleCodesAsync()
    {
        var store = Store();
        await store.GetActiveModuleCodesAsync(TenantA);

        (await store.IsModuleActiveAsync(TenantA, "sales")).Should().BeTrue();

        await _inner.Received(1).GetActiveModuleCodesAsync(TenantA);
    }

    [Fact]
    public async Task GetActiveCatalogAsync_AndGetUserOverridesAsync_ShouldAlwaysReachTheInnerStore()
    {
        IReadOnlyList<SecurityModule> catalog = [];
        IReadOnlyList<UserPermissionOverride> overrides = [];
        _inner.GetActiveCatalogAsync(TenantA).Returns(catalog);
        _inner.GetUserOverridesAsync("u1").Returns(overrides);
        var store = Store();

        await store.GetActiveCatalogAsync(TenantA);
        await store.GetActiveCatalogAsync(TenantA);
        await store.GetUserOverridesAsync("u1");
        await store.GetUserOverridesAsync("u1");

        await _inner.Received(2).GetActiveCatalogAsync(TenantA);
        await _inner.Received(2).GetUserOverridesAsync("u1");
    }

    // ---- invalidation ------------------------------------------------------------------------

    [Fact]
    public async Task InvalidateTenantAsync_ShouldMakeTheNextReadsHitTheInnerStoreAgain()
    {
        var store = Store();
        await store.IsSubscriptionActiveAsync(TenantA);
        await store.GetActiveModuleCodesAsync(TenantA);

        Setup(_inner, active: false);
        await store.InvalidateTenantAsync(TenantA);

        (await store.IsSubscriptionActiveAsync(TenantA)).Should().BeFalse();
        (await store.GetActiveModuleCodesAsync(TenantA)).Should().BeEmpty();
        (await store.IsModuleActiveAsync(TenantA, "SALES")).Should().BeFalse();
        await _inner.Received(2).IsSubscriptionActiveAsync(TenantA);
        await _inner.Received(2).GetActiveModuleCodesAsync(TenantA);
    }

    [Fact]
    public async Task WithoutInvalidation_ShouldKeepServingTheCachedValue_EvenWhenTheInnerStoreChanged()
    {
        var store = Store();
        await store.IsSubscriptionActiveAsync(TenantA);

        Setup(_inner, active: false);

        (await store.IsSubscriptionActiveAsync(TenantA)).Should().BeTrue();
    }

    [Fact]
    public async Task InvalidateTenantAsync_ShouldLeaveOtherTenantsCached()
    {
        var store = Store();
        await store.IsSubscriptionActiveAsync(TenantA);
        await store.IsSubscriptionActiveAsync(TenantB);
        await store.GetActiveModuleCodesAsync(TenantB);

        await store.InvalidateTenantAsync(TenantA);
        await store.IsSubscriptionActiveAsync(TenantA);
        await store.IsSubscriptionActiveAsync(TenantB);
        await store.GetActiveModuleCodesAsync(TenantB);

        await _inner.Received(2).IsSubscriptionActiveAsync(TenantA);
        await _inner.Received(1).IsSubscriptionActiveAsync(TenantB);
        await _inner.Received(1).GetActiveModuleCodesAsync(TenantB);
    }

    [Fact]
    public async Task InvalidateTenantAsync_ShouldNotThrow_WhenNothingWasCachedForTheTenant()
    {
        var act = () => Store().InvalidateTenantAsync(TenantA);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task InvalidateTenantAsync_ShouldForceAFreshReadOnEveryCall()
    {
        var store = Store();
        await store.IsSubscriptionActiveAsync(TenantA);

        await store.InvalidateTenantAsync(TenantA);
        await store.IsSubscriptionActiveAsync(TenantA);
        await store.InvalidateTenantAsync(TenantA);
        await store.IsSubscriptionActiveAsync(TenantA);

        await _inner.Received(3).IsSubscriptionActiveAsync(TenantA);
    }

    [Fact]
    public async Task ALateStaleWrite_ShouldNotBeServed_AfterInvalidation()
    {
        var store = Store();
        await store.IsSubscriptionActiveAsync(TenantA); // creates the generation and an entry
        var oldGeneration = await _cache.GetStringAsync("pinotechrd:security:tenant:" + TenantA + ":gen");
        oldGeneration.Should().NotBeNullOrEmpty();

        await store.InvalidateTenantAsync(TenantA);

        // A reader that loaded before the invalidation stores its stale answer under the generation it had read.
        await _cache.SetAsync(
            "pinotechrd:security:tenant:" + TenantA + ":" + oldGeneration + ":subscription",
            Encoding.UTF8.GetBytes("true"),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5) });
        Setup(_inner, active: false);

        (await store.IsSubscriptionActiveAsync(TenantA)).Should().BeFalse();
        await _inner.Received(2).IsSubscriptionActiveAsync(TenantA);
    }

    // ---- expiration --------------------------------------------------------------------------

    [Fact]
    public async Task Entries_ShouldBeServedUntilTheConfiguredExpiration_ThenReadFresh()
    {
        var clock = new FakeTimeProvider();
        var store = NewStore(_inner, new ClockedDistributedCache(clock), TimeSpan.FromMinutes(2));
        await store.IsSubscriptionActiveAsync(TenantA);

        clock.Advance(TimeSpan.FromMinutes(1) + TimeSpan.FromSeconds(59));
        await store.IsSubscriptionActiveAsync(TenantA);
        await _inner.Received(1).IsSubscriptionActiveAsync(TenantA);

        clock.Advance(TimeSpan.FromSeconds(2));
        Setup(_inner, active: false);
        (await store.IsSubscriptionActiveAsync(TenantA)).Should().BeFalse();
        await _inner.Received(2).IsSubscriptionActiveAsync(TenantA);
    }

    [Fact]
    public async Task Entries_ShouldExpireAbsolutely_EvenWhenTheyAreReadRegularly()
    {
        var clock = new FakeTimeProvider();
        var store = NewStore(_inner, new ClockedDistributedCache(clock), TimeSpan.FromMinutes(2));
        await store.IsSubscriptionActiveAsync(TenantA); // t=0, loads

        // A sliding entry read every 90 seconds would never expire.
        clock.Advance(TimeSpan.FromSeconds(90));
        await store.IsSubscriptionActiveAsync(TenantA); // t=90, cached
        clock.Advance(TimeSpan.FromSeconds(90));
        await store.IsSubscriptionActiveAsync(TenantA); // t=180, expired, loads

        await _inner.Received(2).IsSubscriptionActiveAsync(TenantA);
    }

    [Fact]
    public async Task DefaultExpiration_ShouldKeepEntriesForFourMinutes_AndDropThemAfterFive()
    {
        var clock = new FakeTimeProvider();
        var store = new TenantCacheStore(_inner, new ClockedDistributedCache(clock), MsOptions.Create(new PinotechrdSecurityOptions()));
        await store.IsSubscriptionActiveAsync(TenantA);

        clock.Advance(TimeSpan.FromMinutes(4));
        await store.IsSubscriptionActiveAsync(TenantA);
        await _inner.Received(1).IsSubscriptionActiveAsync(TenantA);

        clock.Advance(TimeSpan.FromMinutes(1.5));
        await store.IsSubscriptionActiveAsync(TenantA);
        await _inner.Received(2).IsSubscriptionActiveAsync(TenantA);
    }

    [Fact]
    public void Options_ShouldDefaultTheExpirationToFiveMinutes()
    {
        new PinotechrdSecurityOptions().TenantCacheExpiration.Should().Be(TimeSpan.FromMinutes(5));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Constructor_ShouldThrow_WhenTheExpirationIsNotPositive(int seconds)
    {
        var act = () => Store(TimeSpan.FromSeconds(seconds));

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentNull_ForMissingDependencies()
    {
        var options = MsOptions.Create(new PinotechrdSecurityOptions());

        ((Action)(() => new TenantCacheStore(null!, _cache, options))).Should().Throw<ArgumentNullException>();
        ((Action)(() => new TenantCacheStore(_inner, null!, options))).Should().Throw<ArgumentNullException>();
        ((Action)(() => new TenantCacheStore(_inner, _cache, null!))).Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public async Task IsModuleActiveAsync_ShouldNormalizeTheStoredCodesToo()
    {
        Setup(_inner, active: true, "sales", " STOCK ");
        var store = Store();

        (await store.IsModuleActiveAsync(TenantA, "SALES")).Should().BeTrue();
        (await store.IsModuleActiveAsync(TenantA, "sales")).Should().BeTrue();
        (await store.IsModuleActiveAsync(TenantA, "stock")).Should().BeTrue();
        (await store.IsModuleActiveAsync(TenantA, "OTHER")).Should().BeFalse();
    }

    [Fact]
    public async Task ReadsFromTheCache_ShouldPropagateTheException_WhenTheDistributedCacheThrows()
    {
        var broken = Substitute.For<IDistributedCache>();
        broken.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns<Task<byte[]?>>(_ => throw new InvalidOperationException("cache down"));
        var store = NewStore(_inner, broken);

        var subscription = () => store.IsSubscriptionActiveAsync(TenantA);
        var module = () => store.IsModuleActiveAsync(TenantA, "SALES");

        await subscription.Should().ThrowAsync<InvalidOperationException>();
        await module.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task AGenerationKeyThatExpiredAndWasRecreated_ShouldMakeTheNextReadHitTheInnerStore()
    {
        var clock = new FakeTimeProvider();
        var cache = new ClockedDistributedCache(clock);
        var store = NewStore(_inner, cache, TimeSpan.FromMinutes(2));
        await store.IsSubscriptionActiveAsync(TenantA);
        var firstGeneration = await cache.GetStringAsync("pinotechrd:security:tenant:" + TenantA + ":gen");

        // The generation lapses (sliding) while the data entry has not: only the generation key is removed.
        await cache.RemoveAsync("pinotechrd:security:tenant:" + TenantA + ":gen");
        Setup(_inner, active: false);

        (await store.IsSubscriptionActiveAsync(TenantA)).Should().BeFalse();
        await _inner.Received(2).IsSubscriptionActiveAsync(TenantA);
        (await cache.GetStringAsync("pinotechrd:security:tenant:" + TenantA + ":gen")).Should().NotBe(firstGeneration);
    }

    [Fact]
    public async Task TheGenerationKey_ShouldExpireSlidingly_AndAnActiveTenantKeepsIt()
    {
        var clock = new FakeTimeProvider();
        var cache = new ClockedDistributedCache(clock);
        var store = NewStore(_inner, cache, TimeSpan.FromMinutes(2));
        var key = "pinotechrd:security:tenant:" + TenantA + ":gen";
        await store.IsSubscriptionActiveAsync(TenantA);
        var generation = await cache.GetStringAsync(key);

        clock.Advance(TimeSpan.FromSeconds(90));
        await store.IsSubscriptionActiveAsync(TenantA);
        clock.Advance(TimeSpan.FromSeconds(90));

        (await cache.GetStringAsync(key)).Should().Be(generation);

        clock.Advance(TimeSpan.FromMinutes(3));
        (await cache.GetStringAsync(key)).Should().BeNull();
    }

    // ---- damaged entries ---------------------------------------------------------------------

    [Fact]
    public async Task AnUndeserializableEntry_ShouldBeTreatedAsAMiss_AndReplaced()
    {
        var store = Store();
        await store.IsSubscriptionActiveAsync(TenantA);
        await store.GetActiveModuleCodesAsync(TenantA);
        var generation = await _cache.GetStringAsync("pinotechrd:security:tenant:" + TenantA + ":gen");
        var prefix = "pinotechrd:security:tenant:" + TenantA + ":" + generation + ":";
        await _cache.SetAsync(prefix + "subscription", Encoding.UTF8.GetBytes("not json{"));
        await _cache.SetAsync(prefix + "modules", Encoding.UTF8.GetBytes("<<garbage>>"));

        (await store.IsSubscriptionActiveAsync(TenantA)).Should().BeTrue();
        (await store.GetActiveModuleCodesAsync(TenantA)).Should().BeEquivalentTo("SALES", "STOCK");
        await _inner.Received(2).IsSubscriptionActiveAsync(TenantA);
        await _inner.Received(2).GetActiveModuleCodesAsync(TenantA);

        // The fresh answer replaced the damaged bytes.
        await store.IsSubscriptionActiveAsync(TenantA);
        await _inner.Received(2).IsSubscriptionActiveAsync(TenantA);
    }

    // ---- invalid tenant ids ------------------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData("TENANT-A")]
    [InlineData("-tenant")]
    [InlineData("tenant:a")]
    [InlineData("tenant_a")]
    public async Task InvalidateTenantAsync_ShouldThrowArgumentException_WhenTheTenantIdIsNotValid(string tenantId)
    {
        var act = () => Store().InvalidateTenantAsync(tenantId);

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task InvalidateTenantAsync_ShouldThrowArgumentException_WhenTheTenantIdIsNull()
    {
        var act = () => Store().InvalidateTenantAsync(null!);

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Theory]
    [InlineData("TENANT-A")]
    [InlineData("tenant:a")]
    [InlineData("-x")]
    public async Task Reads_ShouldPassThroughToTheInnerStoreWithoutCaching_WhenTheTenantIdIsNotValid(string tenantId)
    {
        var store = Store();

        await store.IsSubscriptionActiveAsync(tenantId);
        await store.IsSubscriptionActiveAsync(tenantId);
        await store.GetActiveModuleCodesAsync(tenantId);
        await store.GetActiveModuleCodesAsync(tenantId);
        await store.IsModuleActiveAsync(tenantId, "SALES");

        await _inner.Received(2).IsSubscriptionActiveAsync(tenantId);
        await _inner.Received(2).GetActiveModuleCodesAsync(tenantId);
        await _inner.Received(1).IsModuleActiveAsync(tenantId, "SALES");
        (await _cache.GetAsync("pinotechrd:security:tenant:" + tenantId + ":gen")).Should().BeNull();
    }

    // ---- two instances, one distributed cache ------------------------------------------------

    [Fact]
    public async Task InvalidatingOnOneStore_ShouldMakeAnotherStoreSharingTheCacheReadFreshData()
    {
        var innerB = Substitute.For<ISecurityStore>();
        Setup(innerB, active: true, "SALES");
        var hostA = NewStore(_inner, _cache);
        var hostB = NewStore(innerB, _cache);
        await hostB.IsSubscriptionActiveAsync(TenantA);
        await hostB.GetActiveModuleCodesAsync(TenantA);
        await hostB.IsSubscriptionActiveAsync(TenantA);
        await innerB.Received(1).IsSubscriptionActiveAsync(TenantA);

        Setup(innerB, active: false);
        await hostA.InvalidateTenantAsync(TenantA);

        (await hostB.IsSubscriptionActiveAsync(TenantA)).Should().BeFalse();
        (await hostB.GetActiveModuleCodesAsync(TenantA)).Should().BeEmpty();
        await innerB.Received(2).IsSubscriptionActiveAsync(TenantA);
        await innerB.Received(2).GetActiveModuleCodesAsync(TenantA);
    }

    [Fact]
    public async Task AValueCachedByOneStore_ShouldBeServedToAnotherStoreSharingTheCache()
    {
        var innerB = Substitute.For<ISecurityStore>();
        Setup(innerB, active: false);
        await NewStore(_inner, _cache).IsSubscriptionActiveAsync(TenantA);

        (await NewStore(innerB, _cache).IsSubscriptionActiveAsync(TenantA)).Should().BeTrue();

        await innerB.DidNotReceiveWithAnyArgs().IsSubscriptionActiveAsync(default!);
    }

    [Fact]
    public async Task InvalidatingOnOneStore_ShouldNotAffectAnotherStoresOtherTenant()
    {
        var innerB = Substitute.For<ISecurityStore>();
        Setup(innerB, active: true);
        var hostA = NewStore(_inner, _cache);
        var hostB = NewStore(innerB, _cache);
        await hostB.IsSubscriptionActiveAsync(TenantB);

        await hostA.InvalidateTenantAsync(TenantA);
        await hostB.IsSubscriptionActiveAsync(TenantB);

        await innerB.Received(1).IsSubscriptionActiveAsync(TenantB);
    }

    // ---- helpers -----------------------------------------------------------------------------

    /// <summary>In-memory IDistributedCache whose absolute and sliding expiration follow a controllable clock.</summary>
    private sealed class ClockedDistributedCache(TimeProvider clock) : IDistributedCache
    {
        private sealed class Entry(byte[] value, DateTimeOffset? absolute, TimeSpan? sliding, DateTimeOffset touched)
        {
            public byte[] Value { get; } = value;
            public DateTimeOffset? Absolute { get; } = absolute;
            public TimeSpan? Sliding { get; } = sliding;
            public DateTimeOffset Touched { get; set; } = touched;
        }

        private readonly Dictionary<string, Entry> _entries = [];

        public byte[]? Get(string key)
        {
            var now = clock.GetUtcNow();
            if (!_entries.TryGetValue(key, out var entry))
            {
                return null;
            }

            if ((entry.Absolute is { } abs && now >= abs) || (entry.Sliding is { } slide && now - entry.Touched >= slide))
            {
                _entries.Remove(key);
                return null;
            }

            entry.Touched = now;
            return entry.Value;
        }

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => Task.FromResult(Get(key));

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            var now = clock.GetUtcNow();
            DateTimeOffset? absolute = options.AbsoluteExpiration
                ?? (options.AbsoluteExpirationRelativeToNow is { } rel ? now + rel : null);
            _entries[key] = new Entry(value, absolute, options.SlidingExpiration, now);
        }

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            Set(key, value, options);
            return Task.CompletedTask;
        }

        public void Refresh(string key) => Get(key);

        public Task RefreshAsync(string key, CancellationToken token = default)
        {
            Refresh(key);
            return Task.CompletedTask;
        }

        public void Remove(string key) => _entries.Remove(key);

        public Task RemoveAsync(string key, CancellationToken token = default)
        {
            Remove(key);
            return Task.CompletedTask;
        }
    }
}
