using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Core;

/// <summary>
/// In-memory refresh token store intended as secure baseline behavior.
/// </summary>
public class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private sealed class RefreshTokenEntry
    {
        public required string UserId { get; init; }
        public required string TenantId { get; init; }
        public required DateTime ExpiresAtUtc { get; init; }
        public bool Revoked { get; set; }
    }

    private readonly ConcurrentDictionary<string, RefreshTokenEntry> _tokens = new();

    /// <inheritdoc />
    public Task SaveAsync(string userId, string tenantId, string refreshToken, DateTime expiresAtUtc)
    {
        var tokenHash = HashToken(refreshToken);
        _tokens[tokenHash] = new RefreshTokenEntry
        {
            UserId = userId,
            TenantId = tenantId,
            ExpiresAtUtc = expiresAtUtc,
            Revoked = false
        };

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<RefreshTokenValidationResult> ValidateAsync(string refreshToken)
    {
        var tokenHash = HashToken(refreshToken);
        if (!_tokens.TryGetValue(tokenHash, out var entry))
        {
            return Task.FromResult(new RefreshTokenValidationResult(false, Reason: "Refresh token not found"));
        }

        if (entry.Revoked)
        {
            return Task.FromResult(new RefreshTokenValidationResult(false, Reason: "Refresh token revoked"));
        }

        if (entry.ExpiresAtUtc <= DateTime.UtcNow)
        {
            return Task.FromResult(new RefreshTokenValidationResult(false, Reason: "Refresh token expired"));
        }

        return Task.FromResult(new RefreshTokenValidationResult(true, entry.UserId, entry.TenantId));
    }

    /// <inheritdoc />
    public Task RevokeAsync(string refreshToken)
    {
        var tokenHash = HashToken(refreshToken);
        if (_tokens.TryGetValue(tokenHash, out var entry))
        {
            entry.Revoked = true;
        }

        return Task.CompletedTask;
    }

    private static string HashToken(string token)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexString(bytes);
    }
}
