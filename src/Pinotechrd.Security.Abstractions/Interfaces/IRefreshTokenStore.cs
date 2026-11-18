using System.Threading;

namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Stores and validates opaque refresh tokens bound to user and tenant context.
/// </summary>
/// <remarks>
/// Tokens belong to a family: the first token of a sign-in starts one, and every token issued by rotating it
/// joins the same family. Presenting a token that was already consumed is treated as theft (RFC 9700,
/// section 4.14.2): the store revokes the whole family. Implementations must make
/// <see cref="ConsumeAsync"/> atomic, so that of two concurrent calls with the same token exactly one succeeds.
/// </remarks>
public interface IRefreshTokenStore
{
    /// <summary>
    /// Persists a refresh token for later consumption.
    /// </summary>
    /// <param name="userId">Owner user identifier.</param>
    /// <param name="tenantId">Tenant identifier bound to this token.</param>
    /// <param name="refreshToken">Opaque refresh token value. Store a hash, not the value.</param>
    /// <param name="expiresAtUtc">Expiration date in UTC.</param>
    /// <param name="familyId">Family the token joins. <see langword="null"/> starts a new family.</param>
    /// <param name="securityStamp">Security stamp of the user when the token was issued, if the user store has one.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task SaveAsync(
        string userId,
        string tenantId,
        string refreshToken,
        DateTime expiresAtUtc,
        string? familyId = null,
        string? securityStamp = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Looks a refresh token up without consuming it.
    /// </summary>
    /// <param name="refreshToken">Opaque refresh token value.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<RefreshTokenValidationResult> ValidateAsync(string refreshToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically validates and invalidates a refresh token and returns its data.
    /// </summary>
    /// <remarks>
    /// A token bound to a tenant other than <paramref name="expectedTenantId"/> is not consumed and the result is
    /// <see cref="RefreshTokenConsumeStatus.TenantMismatch"/>. A token that was already consumed revokes its whole
    /// family and the result is <see cref="RefreshTokenConsumeStatus.Reused"/>.
    /// </remarks>
    /// <param name="refreshToken">Opaque refresh token value.</param>
    /// <param name="expectedTenantId">Tenant the current request was resolved for.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<RefreshTokenConsumeResult> ConsumeAsync(string refreshToken, string expectedTenantId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a refresh token so it cannot be reused.
    /// </summary>
    /// <param name="refreshToken">Opaque refresh token value.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task RevokeAsync(string refreshToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every refresh token of a user, in every family and tenant.
    /// </summary>
    /// <param name="userId">Owner user identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Validation result for refresh token lookups.
/// </summary>
/// <param name="IsValid">Indicates whether the token is currently valid.</param>
/// <param name="UserId">Resolved user identifier when the token is valid.</param>
/// <param name="TenantId">Resolved tenant identifier when the token is valid.</param>
/// <param name="Reason">Optional rejection reason when the token is invalid. Do not return it to clients.</param>
public sealed record RefreshTokenValidationResult(
    bool IsValid,
    string? UserId = null,
    string? TenantId = null,
    string? Reason = null
);

/// <summary>
/// Outcome of <see cref="IRefreshTokenStore.ConsumeAsync"/>.
/// </summary>
public enum RefreshTokenConsumeStatus
{
    /// <summary>The token was valid and is now consumed.</summary>
    Consumed = 0,

    /// <summary>No such token.</summary>
    NotFound = 1,

    /// <summary>The token expired.</summary>
    Expired = 2,

    /// <summary>The token, or its family, was revoked.</summary>
    Revoked = 3,

    /// <summary>The token was already consumed; its family is now revoked.</summary>
    Reused = 4,

    /// <summary>The token belongs to another tenant. It was not consumed.</summary>
    TenantMismatch = 5
}

/// <summary>
/// Result of <see cref="IRefreshTokenStore.ConsumeAsync"/>.
/// </summary>
/// <param name="Status">Outcome of the call.</param>
/// <param name="UserId">Owner user identifier, when consumed.</param>
/// <param name="TenantId">Tenant bound to the token, when consumed.</param>
/// <param name="FamilyId">Family of the token, when consumed.</param>
/// <param name="SecurityStamp">Security stamp captured when the token was issued, when consumed.</param>
public sealed record RefreshTokenConsumeResult(
    RefreshTokenConsumeStatus Status,
    string? UserId = null,
    string? TenantId = null,
    string? FamilyId = null,
    string? SecurityStamp = null)
{
    /// <summary>
    /// <see langword="true"/> when <see cref="Status"/> is <see cref="RefreshTokenConsumeStatus.Consumed"/>.
    /// </summary>
    public bool Succeeded => Status == RefreshTokenConsumeStatus.Consumed;
}
