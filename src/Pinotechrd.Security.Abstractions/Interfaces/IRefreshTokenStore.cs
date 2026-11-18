namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Stores and validates opaque refresh tokens bound to user and tenant context.
/// </summary>
public interface IRefreshTokenStore
{
    /// <summary>
    /// Persists a refresh token for later validation.
    /// </summary>
    /// <param name="userId">Owner user identifier.</param>
    /// <param name="tenantId">Tenant identifier bound to this token.</param>
    /// <param name="refreshToken">Opaque refresh token value.</param>
    /// <param name="expiresAtUtc">Expiration date in UTC.</param>
    Task SaveAsync(string userId, string tenantId, string refreshToken, DateTime expiresAtUtc);

    /// <summary>
    /// Validates a refresh token and returns contextual data when valid.
    /// </summary>
    /// <param name="refreshToken">Opaque refresh token value.</param>
    Task<RefreshTokenValidationResult> ValidateAsync(string refreshToken);

    /// <summary>
    /// Revokes a refresh token so it cannot be reused.
    /// </summary>
    /// <param name="refreshToken">Opaque refresh token value.</param>
    Task RevokeAsync(string refreshToken);
}

/// <summary>
/// Validation result for refresh token lookups.
/// </summary>
/// <param name="IsValid">Indicates whether the token is currently valid.</param>
/// <param name="UserId">Resolved user identifier when the token is valid.</param>
/// <param name="TenantId">Resolved tenant identifier when the token is valid.</param>
/// <param name="Reason">Optional rejection reason when the token is invalid.</param>
public sealed record RefreshTokenValidationResult(
    bool IsValid,
    string? UserId = null,
    string? TenantId = null,
    string? Reason = null
);
