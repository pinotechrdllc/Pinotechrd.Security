using Microsoft.Extensions.Logging;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;
using Pinotechrd.Security.Options;
using Pinotechrd.Security.Tenancy;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Decorator for <see cref="ISecurityStore"/> that caches a tenant's subscription state and active module codes in
/// an <see cref="IDistributedCache"/>, and invalidates them on demand.
/// </summary>
/// <remarks>
/// <para>
/// Each tenant has a generation key, <c>pinotechrd:security:tenant:{tenantId}:gen</c>, holding a random token. The
/// cached entries are stored under keys that include it (<c>pinotechrd:security:tenant:{tenantId}:{generation}:subscription</c>
/// and <c>...:modules</c>). <see cref="InvalidateTenantAsync"/> writes a new generation, so every instance sharing the
/// cache stops reading the old entries, which then expire. The generation is read from the distributed cache on every
/// call, never kept per instance. A read that loaded data before an invalidation stores it under the old generation,
/// where nobody reads it, so it cannot bring back stale data.
/// </para>
/// <para>
/// <see cref="IsModuleActiveAsync"/> is answered from the cached module codes. The plan catalog and the user overrides
/// are never cached. A tenant identifier that is not well-formed is passed to the inner store without caching.
/// </para>
/// </remarks>
public class TenantCacheStore : ISecurityStore, ISecurityCacheInvalidator
{
    private const string KeyPrefix = "pinotechrd:security:tenant:";

    private readonly ISecurityStore _inner;
    private readonly IDistributedCache _cache;
    private readonly TimeSpan _expiration;
    private readonly ILogger? _events;

    /// <summary>
    /// Initializes a new instance of the <see cref="TenantCacheStore"/> class.
    /// </summary>
    /// <param name="inner">The inner store implementation.</param>
    /// <param name="cache">The distributed cache shared by every instance of the application.</param>
    /// <param name="options">Security options; <see cref="PinotechrdSecurityOptions.TenantCacheExpiration"/> sets how
    /// long an entry is kept.</param>
    /// <param name="loggerFactory">Logs <see cref="SecurityEvents.TenantCacheInvalidated"/>; optional.</param>
    public TenantCacheStore(ISecurityStore inner, IDistributedCache cache, IOptions<PinotechrdSecurityOptions> options, ILoggerFactory? loggerFactory = null)
    {
        _events = SecurityLog.Create(loggerFactory);
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(options);

        _inner = inner;
        _cache = cache;
        _expiration = options.Value.TenantCacheExpiration;
        if (_expiration <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "PinotechrdSecurityOptions.TenantCacheExpiration must be positive.");
        }
    }

    /// <inheritdoc />
    public async Task<bool> IsSubscriptionActiveAsync(string tenantId, CancellationToken cancellationToken = default)
    {
        if (!TenantIdentifier.IsValid(tenantId))
        {
            return await _inner.IsSubscriptionActiveAsync(tenantId, cancellationToken);
        }

        var key = await DataKeyAsync(tenantId, "subscription", cancellationToken);
        var cached = await ReadAsync<bool?>(key, cancellationToken);
        if (cached.HasValue)
        {
            return cached.Value;
        }

        var isActive = await _inner.IsSubscriptionActiveAsync(tenantId, cancellationToken);
        await WriteAsync<bool?>(key, isActive, cancellationToken);
        return isActive;
    }

    /// <inheritdoc />
    public async Task<bool> IsModuleActiveAsync(string tenantId, string moduleCode, CancellationToken cancellationToken = default)
    {
        if (!TenantIdentifier.IsValid(tenantId))
        {
            return await _inner.IsModuleActiveAsync(tenantId, moduleCode, cancellationToken);
        }

        if (!SecurityCodes.TryNormalize(moduleCode, out var code))
        {
            return false;
        }

        // Stored codes are normalized the same way before comparing, matching SecurityEngine, so a row written
        // outside the seeder (lower case, surrounding spaces) is not denied here while the menu still shows it.
        var codes = await GetActiveModuleCodesAsync(tenantId, cancellationToken);
        return codes.Any(stored => SecurityCodes.TryNormalize(stored, out var normalized)
            && string.Equals(normalized, code, StringComparison.Ordinal));
    }

    /// <inheritdoc />
    public async Task<IEnumerable<string>> GetActiveModuleCodesAsync(string tenantId, CancellationToken cancellationToken = default)
    {
        if (!TenantIdentifier.IsValid(tenantId))
        {
            return await _inner.GetActiveModuleCodesAsync(tenantId, cancellationToken);
        }

        var key = await DataKeyAsync(tenantId, "modules", cancellationToken);
        var cached = await ReadAsync<string[]>(key, cancellationToken);
        if (cached is not null)
        {
            return cached;
        }

        var codes = (await _inner.GetActiveModuleCodesAsync(tenantId, cancellationToken)).ToArray();
        await WriteAsync(key, codes, cancellationToken);
        return codes;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<SecurityModule>> GetActiveCatalogAsync(string tenantId, CancellationToken cancellationToken = default)
    {
        // The catalog is what an administrator is editing. Caching it would keep a module on screen after the plan
        // turned it off.
        return _inner.GetActiveCatalogAsync(tenantId, cancellationToken);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<UserPermissionOverride>> GetUserOverridesAsync(string userId, CancellationToken cancellationToken = default)
    {
        // A deny has to win on the next request. Caching it would leave the
        // blocked permission usable until the entry expired.
        return _inner.GetUserOverridesAsync(userId, cancellationToken);
    }

    /// <inheritdoc />
    public async Task InvalidateTenantAsync(string tenantId, CancellationToken cancellationToken = default)
    {
        if (!TenantIdentifier.IsValid(tenantId))
        {
            throw new ArgumentException("Tenant ID is not a valid tenant identifier.", nameof(tenantId));
        }

        // Entries written under the old generation, including one a concurrent read is storing right now from data
        // loaded before the change, are never read again.
        await WriteGenerationAsync(GenerationKey(tenantId), NewGeneration(), cancellationToken);
        SecurityLog.TenantCacheInvalidated(_events, tenantId);
    }

    private static string GenerationKey(string tenantId) => KeyPrefix + tenantId + ":gen";

    private static string NewGeneration() => Guid.NewGuid().ToString("N");

    private async Task<string> DataKeyAsync(string tenantId, string entry, CancellationToken cancellationToken)
    {
        // Read from the shared cache every time: a generation kept per instance would hide an invalidation made on
        // another instance.
        var generationKey = GenerationKey(tenantId);
        var generation = await _cache.GetStringAsync(generationKey, cancellationToken);
        if (string.IsNullOrEmpty(generation))
        {
            generation = NewGeneration();
            await WriteGenerationAsync(generationKey, generation, cancellationToken);
        }

        return KeyPrefix + tenantId + ":" + generation + ":" + entry;
    }

    private Task WriteGenerationAsync(string generationKey, string generation, CancellationToken cancellationToken)
    {
        // Sliding, so an active tenant keeps its generation; when it lapses only cache misses follow, because the
        // entries of the old generation are never read again.
        return _cache.SetStringAsync(
            generationKey,
            generation,
            new DistributedCacheEntryOptions { SlidingExpiration = _expiration },
            cancellationToken);
    }

    private async Task<T?> ReadAsync<T>(string key, CancellationToken cancellationToken)
    {
        var bytes = await _cache.GetAsync(key, cancellationToken);
        if (bytes is null)
        {
            return default;
        }

        try
        {
            return JsonSerializer.Deserialize<T>(bytes);
        }
        catch (JsonException)
        {
            // An unreadable entry is a miss: the store is the source of truth.
            return default;
        }
    }

    private Task WriteAsync<T>(string key, T value, CancellationToken cancellationToken)
    {
        return _cache.SetAsync(
            key,
            JsonSerializer.SerializeToUtf8Bytes(value),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = _expiration },
            cancellationToken);
    }
}
