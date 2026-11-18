using Microsoft.Extensions.Caching.Memory;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Decorator for ISecurityStore that adds MemoryCache support.
/// </summary>
public class TenantCacheStore : ISecurityStore
{
    private readonly ISecurityStore _inner;
    private readonly IMemoryCache _cache;
    private static readonly TimeSpan DefaultExpiration = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Initializes a new instance of the <see cref="TenantCacheStore"/> class.
    /// </summary>
    /// <param name="inner">The inner store implementation.</param>
    /// <param name="cache">The memory cache instance.</param>
    public TenantCacheStore(ISecurityStore inner, IMemoryCache cache)
    {
        _inner = inner;
        _cache = cache;
    }

    /// <inheritdoc />
    public async Task<bool> IsSubscriptionActiveAsync(string tenantId)
    {
        var cacheKey = $"security:subscription:{tenantId}";
        
        if (_cache.TryGetValue(cacheKey, out bool isActive))
        {
            return isActive;
        }

        isActive = await _inner.IsSubscriptionActiveAsync(tenantId);
        _cache.Set(cacheKey, isActive, DefaultExpiration);
        
        return isActive;
    }

    /// <inheritdoc />
    public async Task<bool> IsModuleActiveAsync(string tenantId, string moduleCode)
    {
        var cacheKey = $"security:module:{tenantId}:{moduleCode}";
        
        if (_cache.TryGetValue(cacheKey, out bool isActive))
        {
            return isActive;
        }

        isActive = await _inner.IsModuleActiveAsync(tenantId, moduleCode);
        _cache.Set(cacheKey, isActive, DefaultExpiration);
        
        return isActive;
    }

    /// <inheritdoc />
    public async Task<IEnumerable<string>> GetActiveModuleCodesAsync(string tenantId)
    {
        var cacheKey = $"security:modules:codes:{tenantId}";
        
        if (_cache.TryGetValue(cacheKey, out IEnumerable<string>? codes) && codes != null)
        {
            return codes;
        }

        codes = await _inner.GetActiveModuleCodesAsync(tenantId);
        _cache.Set(cacheKey, codes, DefaultExpiration);
        
        return codes;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<SecurityModule>> GetActiveCatalogAsync(string tenantId)
    {
        // The catalog is what an administrator is editing. A fifteen-minute
        // cache would keep a module on screen after the plan turned it off.
        return _inner.GetActiveCatalogAsync(tenantId);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<UserPermissionOverride>> GetUserOverridesAsync(string userId)
    {
        // A deny has to win on the next request. Caching it would leave the
        // blocked permission usable until the entry expired.
        return _inner.GetUserOverridesAsync(userId);
    }
}
