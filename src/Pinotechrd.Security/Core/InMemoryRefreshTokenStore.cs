using System.Collections.Concurrent;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Core;

/// <summary>
/// In-memory refresh token store intended as secure baseline behavior.
/// </summary>
/// <remarks>
/// <para>
/// Thread safe: <see cref="ConsumeAsync"/> lets exactly one of several concurrent calls with the same token succeed.
/// Follows the rules of <see cref="IRefreshTokenStore"/>; expiry is decided by the injected <see cref="TimeProvider"/>.
/// Tokens are lost on restart and are not shared between instances.
/// </para>
/// <para>
/// When more than 10,000 tokens are held, saving a token first drops the tokens of every family whose tokens
/// have all expired, and every revoked family past its latest expiry; the next purge waits until the store has
/// doubled. A consumed or expired token is kept while its family still has a live token, so its replay is
/// still <see cref="RefreshTokenConsumeStatus.Reused"/> and revokes the family.
/// </para>
/// </remarks>
public class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private const int MinimumPurgeThreshold = 10_000;

    private sealed class RefreshTokenEntry
    {
        public required string UserId { get; init; }
        public required string TenantId { get; init; }
        public required string FamilyId { get; init; }
        public string? SecurityStamp { get; init; }
        public required DateTime ExpiresAtUtc { get; init; }
        public bool Revoked { get; set; }
        public bool Consumed { get; set; }
    }

    private readonly ConcurrentDictionary<string, RefreshTokenEntry> _tokens = new();
    // Revoked family id -> latest expiry of its tokens; kept until that expiry so late saves stay refused.
    private readonly ConcurrentDictionary<string, DateTime> _revokedFamilies = new();
    // Family id -> latest expiry of any token saved into it. A token is kept until its whole family has expired,
    // so replaying an old, consumed token is still recognised as reuse while the family has live tokens.
    private readonly ConcurrentDictionary<string, DateTime> _familyExpiry = new();
    // Family id -> the user and tenant that started it, kept as long as _familyExpiry keeps the family.
    private readonly ConcurrentDictionary<string, (string UserId, string TenantId)> _familyOwners = new();
    private readonly TimeProvider _timeProvider;
    private readonly object _purgeLock = new();
    private int _purgeThreshold = MinimumPurgeThreshold;

    /// <summary>
    /// Initializes the store with the system clock.
    /// </summary>
    public InMemoryRefreshTokenStore() : this(TimeProvider.System)
    {
    }

    /// <summary>
    /// Initializes the store with the given clock.
    /// </summary>
    public InMemoryRefreshTokenStore(TimeProvider timeProvider)
    {
        _timeProvider = timeProvider;
    }

    private DateTime UtcNow => _timeProvider.GetUtcNow().UtcDateTime;

    /// <inheritdoc />
    /// <exception cref="InvalidOperationException">The token value is already stored.</exception>
    public Task SaveAsync(
        string userId,
        string tenantId,
        string refreshToken,
        DateTime expiresAtUtc,
        string? familyId = null,
        string? securityStamp = null,
        CancellationToken cancellationToken = default)
    {
        PurgeIfLarge();

        var family = familyId ?? Guid.NewGuid().ToString("N");
        var entry = new RefreshTokenEntry
        {
            UserId = userId,
            TenantId = tenantId,
            FamilyId = family,
            SecurityStamp = securityStamp,
            ExpiresAtUtc = expiresAtUtc
        };

        if (!_tokens.TryAdd(HashToken(refreshToken), entry))
        {
            throw new InvalidOperationException("This refresh token is already stored.");
        }

        _familyOwners.TryAdd(family, (userId, tenantId));
        _familyExpiry.AddOrUpdate(family, expiresAtUtc, (_, existing) => existing > expiresAtUtc ? existing : expiresAtUtc);

        // A token saved into a family revoked meanwhile (for example by a concurrent reuse) is born revoked.
        if (_revokedFamilies.TryGetValue(family, out var familyExpiry))
        {
            lock (entry)
            {
                entry.Revoked = true;
            }

            _revokedFamilies[family] = familyExpiry > expiresAtUtc ? familyExpiry : expiresAtUtc;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    /// <remarks>
    /// The family must have been started by <paramref name="userId"/> in <paramref name="tenantId"/>, still have a token
    /// that has not expired, and not be revoked; a purged family is never recreated.
    /// </remarks>
    /// <exception cref="InvalidOperationException">The token value is already stored.</exception>
    public async Task<bool> RotateAsync(
        string familyId,
        string userId,
        string tenantId,
        string refreshToken,
        DateTime expiresAtUtc,
        string? securityStamp = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(familyId);
        if (!_familyOwners.TryGetValue(familyId, out var owner)
            || !string.Equals(owner.UserId, userId, StringComparison.Ordinal)
            || !string.Equals(owner.TenantId, tenantId, StringComparison.Ordinal)
            || !_familyExpiry.TryGetValue(familyId, out var latest)
            || latest <= UtcNow
            || _revokedFamilies.ContainsKey(familyId))
        {
            return false;
        }

        await SaveAsync(userId, tenantId, refreshToken, expiresAtUtc, familyId, securityStamp, cancellationToken);
        return true;
    }

    /// <inheritdoc />
    public Task<RefreshTokenValidationResult> ValidateAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        if (!_tokens.TryGetValue(HashToken(refreshToken), out var entry))
        {
            return Task.FromResult(new RefreshTokenValidationResult(false, Reason: "Refresh token not found"));
        }

        lock (entry)
        {
            if (entry.Revoked || _revokedFamilies.ContainsKey(entry.FamilyId))
            {
                return Task.FromResult(new RefreshTokenValidationResult(false, Reason: "Refresh token revoked"));
            }

            if (entry.Consumed)
            {
                return Task.FromResult(new RefreshTokenValidationResult(false, Reason: "Refresh token already used"));
            }

            if (entry.ExpiresAtUtc <= UtcNow)
            {
                return Task.FromResult(new RefreshTokenValidationResult(false, Reason: "Refresh token expired"));
            }

            return Task.FromResult(new RefreshTokenValidationResult(true, entry.UserId, entry.TenantId));
        }
    }

    /// <inheritdoc />
    public Task<RefreshTokenConsumeResult> ConsumeAsync(string refreshToken, string expectedTenantId, CancellationToken cancellationToken = default)
    {
        if (!_tokens.TryGetValue(HashToken(refreshToken), out var entry))
        {
            return Task.FromResult(new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.NotFound));
        }

        if (!string.Equals(entry.TenantId, expectedTenantId, StringComparison.Ordinal))
        {
            return Task.FromResult(new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.TenantMismatch));
        }

        lock (entry)
        {
            if (_revokedFamilies.ContainsKey(entry.FamilyId))
            {
                return Task.FromResult(new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Revoked));
            }

            if (!entry.Consumed)
            {
                if (entry.Revoked)
                {
                    return Task.FromResult(new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Revoked));
                }

                if (entry.ExpiresAtUtc <= UtcNow)
                {
                    return Task.FromResult(new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Expired));
                }

                entry.Consumed = true;
                return Task.FromResult(new RefreshTokenConsumeResult(
                    RefreshTokenConsumeStatus.Consumed,
                    entry.UserId,
                    entry.TenantId,
                    entry.FamilyId,
                    entry.SecurityStamp));
            }
        }

        // Already consumed: reuse, even if the token has expired or was revoked on its own since.
        RevokeFamily(entry.FamilyId);
        return Task.FromResult(new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Reused, entry.UserId, entry.TenantId, entry.FamilyId));
    }

    /// <inheritdoc />
    public Task RevokeAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        if (_tokens.TryGetValue(HashToken(refreshToken), out var entry))
        {
            lock (entry)
            {
                entry.Revoked = true;
            }
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        var families = _tokens.Values
            .Where(entry => string.Equals(entry.UserId, userId, StringComparison.Ordinal))
            .Select(entry => entry.FamilyId)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        // Revoking the families also covers a token a concurrent rotation saves after this call.
        foreach (var family in families)
        {
            RevokeFamily(family);
        }

        return Task.CompletedTask;
    }

    private void RevokeFamily(string familyId)
    {
        var latestExpiry = UtcNow;
        _revokedFamilies.AddOrUpdate(familyId, latestExpiry, (_, existing) => existing);

        foreach (var entry in _tokens.Values)
        {
            if (!string.Equals(entry.FamilyId, familyId, StringComparison.Ordinal)) continue;
            lock (entry)
            {
                entry.Revoked = true;
            }

            if (entry.ExpiresAtUtc > latestExpiry) latestExpiry = entry.ExpiresAtUtc;
        }

        _revokedFamilies.AddOrUpdate(familyId, latestExpiry, (_, existing) => existing > latestExpiry ? existing : latestExpiry);
    }

    private void PurgeIfLarge()
    {
        if (_tokens.Count + _revokedFamilies.Count <= Volatile.Read(ref _purgeThreshold)) return;
        if (!Monitor.TryEnter(_purgeLock)) return;
        try
        {
            var now = UtcNow;
            foreach (var (hash, entry) in _tokens)
            {
                // Only when the whole family has expired; a consumed token of a live family must stay to detect reuse.
                var familyExpiry = _familyExpiry.TryGetValue(entry.FamilyId, out var latest) ? latest : entry.ExpiresAtUtc;
                if (familyExpiry <= now) _tokens.TryRemove(hash, out _);
            }

            foreach (var (family, expiry) in _familyExpiry)
            {
                if (expiry <= now && _familyExpiry.TryRemove(family, out _)) _familyOwners.TryRemove(family, out _);
            }

            foreach (var (family, expiry) in _revokedFamilies)
            {
                if (expiry <= now) _revokedFamilies.TryRemove(family, out _);
            }

            Volatile.Write(ref _purgeThreshold, Math.Max(MinimumPurgeThreshold, 2 * (_tokens.Count + _revokedFamilies.Count)));
            // _familyExpiry has at most one entry per family with stored tokens, so it shrinks with _tokens.
        }
        finally
        {
            Monitor.Exit(_purgeLock);
        }
    }

    private static string HashToken(string token) => RefreshTokenHash.ComputeHex(token);
}
