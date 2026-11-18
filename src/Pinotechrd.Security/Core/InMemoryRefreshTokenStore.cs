using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Core;

/// <summary>
/// In-memory refresh token store intended as secure baseline behavior.
/// </summary>
/// <remarks>
/// Thread safe: <see cref="ConsumeAsync"/> lets exactly one of several concurrent calls with the same token succeed.
/// Tokens are lost on restart and are not shared between instances. Expired entries are not purged.
/// </remarks>
public class InMemoryRefreshTokenStore : IRefreshTokenStore
{
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
    private readonly ConcurrentDictionary<string, byte> _revokedFamilies = new();
    private readonly TimeProvider _timeProvider;

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

    /// <inheritdoc />
    public Task SaveAsync(
        string userId,
        string tenantId,
        string refreshToken,
        DateTime expiresAtUtc,
        string? familyId = null,
        string? securityStamp = null,
        CancellationToken cancellationToken = default)
    {
        var family = familyId ?? Guid.NewGuid().ToString("N");
        _tokens[HashToken(refreshToken)] = new RefreshTokenEntry
        {
            UserId = userId,
            TenantId = tenantId,
            FamilyId = family,
            SecurityStamp = securityStamp,
            ExpiresAtUtc = expiresAtUtc,
            // A token saved into a family revoked meanwhile (for example by a concurrent reuse) is born revoked.
            Revoked = _revokedFamilies.ContainsKey(family)
        };

        return Task.CompletedTask;
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

            if (entry.ExpiresAtUtc <= _timeProvider.GetUtcNow().UtcDateTime)
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

        bool reused;
        lock (entry)
        {
            if (entry.Revoked || _revokedFamilies.ContainsKey(entry.FamilyId))
            {
                return Task.FromResult(new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Revoked));
            }

            reused = entry.Consumed;
            if (!reused)
            {
                if (entry.ExpiresAtUtc <= _timeProvider.GetUtcNow().UtcDateTime)
                {
                    return Task.FromResult(new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Expired));
                }

                entry.Consumed = true;
            }
        }

        if (reused)
        {
            RevokeFamily(entry.FamilyId);
            return Task.FromResult(new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Reused));
        }

        return Task.FromResult(new RefreshTokenConsumeResult(
            RefreshTokenConsumeStatus.Consumed,
            entry.UserId,
            entry.TenantId,
            entry.FamilyId,
            entry.SecurityStamp));
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
        foreach (var entry in _tokens.Values)
        {
            if (!string.Equals(entry.UserId, userId, StringComparison.Ordinal)) continue;

            // Revoking the family also covers a token a concurrent rotation saves after this loop.
            _revokedFamilies.TryAdd(entry.FamilyId, 0);
            lock (entry)
            {
                entry.Revoked = true;
            }
        }

        return Task.CompletedTask;
    }

    private void RevokeFamily(string familyId)
    {
        _revokedFamilies.TryAdd(familyId, 0);
        foreach (var entry in _tokens.Values)
        {
            if (!string.Equals(entry.FamilyId, familyId, StringComparison.Ordinal)) continue;
            lock (entry)
            {
                entry.Revoked = true;
            }
        }
    }

    private static string HashToken(string token)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexString(bytes);
    }
}
