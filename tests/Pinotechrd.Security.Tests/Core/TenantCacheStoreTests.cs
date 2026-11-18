using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

public class TenantCacheStoreTests
{
    private readonly ISecurityStore _innerStore = Substitute.For<ISecurityStore>();
    private readonly IMemoryCache _cache = Substitute.For<IMemoryCache>();
    private readonly TenantCacheStore _decorator;

    public TenantCacheStoreTests()
    {
        _decorator = new TenantCacheStore(_innerStore, _cache);
    }

    [Fact]
    public async Task IsSubscriptionActiveAsync_ShouldCallInnerAndCache_WhenNotCached()
    {
        // Arrange
        var tenantId = "T1";
        object? cachedValue = null;
        _cache.TryGetValue(Arg.Any<string>(), out cachedValue).Returns(false);
        _innerStore.IsSubscriptionActiveAsync(tenantId).Returns(true);

        // Act
        var result = await _decorator.IsSubscriptionActiveAsync(tenantId);

        // Assert
        result.Should().BeTrue();
        await _innerStore.Received(1).IsSubscriptionActiveAsync(tenantId);
    }

    [Fact]
    public async Task IsSubscriptionActiveAsync_ShouldReturnCachedValue_WhenCached()
    {
        // Arrange
        var tenantId = "T1";
        object cachedValue = true;
        _cache.TryGetValue(Arg.Is<string>(s => s.Contains(tenantId)), out Arg.Any<object?>())
              .Returns(x => { x[1] = cachedValue; return true; });

        // Act
        var result = await _decorator.IsSubscriptionActiveAsync(tenantId);

        // Assert
        result.Should().BeTrue();
        await _innerStore.DidNotReceive().IsSubscriptionActiveAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task GetActiveCatalogAsync_ShouldCallInnerEveryTime()
    {
        _innerStore.GetActiveCatalogAsync("T1").Returns(new List<SecurityModule>());

        await _decorator.GetActiveCatalogAsync("T1");
        await _decorator.GetActiveCatalogAsync("T1");

        await _innerStore.Received(2).GetActiveCatalogAsync("T1");
    }

    [Fact]
    public async Task GetUserOverridesAsync_ShouldCallInnerEveryTime()
    {
        _innerStore.GetUserOverridesAsync("user-1").Returns(new List<UserPermissionOverride>
        {
            new("MOD_A.PERM_1", PermissionAccessType.Deny)
        });

        var first = await _decorator.GetUserOverridesAsync("user-1");
        var second = await _decorator.GetUserOverridesAsync("user-1");

        first.Should().ContainSingle();
        second.Should().ContainSingle();
        await _innerStore.Received(2).GetUserOverridesAsync("user-1");
    }
}
