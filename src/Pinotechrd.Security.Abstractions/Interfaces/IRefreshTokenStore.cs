using System.Threading;

namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Stores and validates opaque refresh tokens bound to user and tenant context.
/// </summary>
/// <remarks>
/// <para>
/// Tokens belong to a family: the first token of a sign-in starts one (<see cref="SaveAsync"/>), and every token
/// issued by rotating it joins the same family (<see cref="RotateAsync"/>). Presenting a token that was already consumed is treated as theft (RFC 9700,
/// section 4.14.2): the store revokes the whole family. Implementations must make
/// <see cref="ConsumeAsync"/> atomic, so that of two concurrent calls with the same token exactly one succeeds.
/// </para>
/// <para>Rules every implementation must follow:</para>
/// <list type="bullet">
/// <item><description>A revoked family stays revoked. A token saved into it later must never be consumed
/// (store it revoked, or refuse it), including a token saved by a rotation that raced the revocation.</description></item>
/// <item><description><see cref="ConsumeAsync"/> decides in this order: unknown token, <see cref="RefreshTokenConsumeStatus.NotFound"/>;
/// token of another tenant, <see cref="RefreshTokenConsumeStatus.TenantMismatch"/> (nothing changes); family
/// revoked, <see cref="RefreshTokenConsumeStatus.Revoked"/>; token already consumed,
/// <see cref="RefreshTokenConsumeStatus.Reused"/> and the family is revoked, even when the token has also expired
/// or was revoked on its own; token revoked, <see cref="RefreshTokenConsumeStatus.Revoked"/>; token expired,
/// <see cref="RefreshTokenConsumeStatus.Expired"/>; otherwise it is consumed.</description></item>
/// <item><description>Expiry is decided by the store's own clock against the <c>expiresAtUtc</c> given to
/// <see cref="SaveAsync"/>. The built-in stores read an injected <see cref="TimeProvider"/> once per call and,
/// in a database, send that instant as a parameter of the atomic consume. A store may use the database clock
/// (<c>now()</c>) instead; then keep application and database clocks synchronised.</description></item>
/// <item><description><see cref="RotateAsync"/> saves into a family only while the store still has it, for that user
/// and tenant, with a token that has not expired (consumed tokens count: the one just consumed usually is the only
/// one), and it is not revoked; otherwise it returns <see langword="false"/>
/// and stores nothing. A family the store purged or never issued is never recreated.</description></item>
/// <item><description>Saving a token value that already exists must not reset its state; refuse it.</description></item>
/// <item><description>Store a hash of the token (for example SHA-256), never the token itself.</description></item>
/// </list>
/// <para>
/// PostgreSQL sketch of the atomic consume (one statement; zero rows means "not consumed", and a second,
/// non-critical query classifies why and revokes the family on reuse):
/// </para>
/// <code>
/// UPDATE refresh_tokens t SET consumed_at = now()
/// WHERE t.token_hash = @hash AND t.tenant_id = @tenant
///   AND t.consumed_at IS NULL AND t.revoked_at IS NULL AND t.expires_at &gt; now()
///   AND NOT EXISTS (SELECT 1 FROM refresh_token_families f WHERE f.family_id = t.family_id AND f.revoked_at IS NOT NULL)
/// RETURNING t.user_id, t.tenant_id, t.family_id, t.security_stamp;
/// </code>
/// </remarks>
public interface IRefreshTokenStore
{
    /// <summary>
    /// Persists the first refresh token of a sign-in, starting a new family.
    /// </summary>
    /// <remarks>
    /// The library always passes <see langword="null"/> for <paramref name="familyId"/>, so the store chooses the id;
    /// it calls <see cref="RotateAsync"/> for a token that replaces a consumed one. A store may refuse a non-null
    /// <paramref name="familyId"/> (throw <see cref="NotSupportedException"/>).
    /// </remarks>
    /// <param name="userId">Owner user identifier.</param>
    /// <param name="tenantId">Tenant identifier bound to this token.</param>
    /// <param name="refreshToken">Opaque refresh token value. Store a hash, not the value.</param>
    /// <param name="expiresAtUtc">Expiration date in UTC.</param>
    /// <param name="familyId">Family id for the new family; <see langword="null"/> (what the library passes) lets the
    /// store choose one.</param>
    /// <param name="securityStamp">Security stamp of the user when the token was issued, if the user store has one.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="InvalidOperationException">The token value is already stored (implementations should refuse duplicates).</exception>
    Task SaveAsync(
        string userId,
        string tenantId,
        string refreshToken,
        DateTime expiresAtUtc,
        string? familyId = null,
        string? securityStamp = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Persists the refresh token that replaces a consumed one in its family (rotation).
    /// </summary>
    /// <remarks>
    /// Called by <c>RefreshAsync</c> right after <see cref="ConsumeAsync"/> returned
    /// <see cref="RefreshTokenConsumeStatus.Consumed"/> with <paramref name="familyId"/>. Return
    /// <see langword="false"/>, storing nothing, when the family is not one the store still has for
    /// <paramref name="userId"/> in <paramref name="tenantId"/> with an unexpired token (never issued, purged, or
    /// expired), or when it is revoked; the refresh then fails and the user signs in again. Consumed tokens count as the
    /// family's tokens: the token <c>RefreshAsync</c> has just consumed is usually the only one. A family revoked after
    /// this check must still never be consumed (see the rules above). PostgreSQL sketch of the check:
    /// <code>
    /// SELECT EXISTS (SELECT 1 FROM refresh_tokens t
    ///                WHERE t.family_id = @family AND t.user_id = @user AND t.tenant_id = @tenant AND t.expires_at &gt; now())
    ///    AND NOT EXISTS (SELECT 1 FROM refresh_token_families f WHERE f.family_id = @family AND f.revoked_at IS NOT NULL);
    /// </code>
    /// </remarks>
    /// <param name="familyId">Family of the consumed token.</param>
    /// <param name="userId">Owner user identifier.</param>
    /// <param name="tenantId">Tenant identifier bound to this token.</param>
    /// <param name="refreshToken">Opaque refresh token value. Store a hash, not the value.</param>
    /// <param name="expiresAtUtc">Expiration date in UTC.</param>
    /// <param name="securityStamp">Security stamp of the user when the token was issued, if the user store has one.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> when the token was stored in the family.</returns>
    /// <exception cref="InvalidOperationException">The token value is already stored.</exception>
    Task<bool> RotateAsync(
        string familyId,
        string userId,
        string tenantId,
        string refreshToken,
        DateTime expiresAtUtc,
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
    /// Revokes every refresh token of a user that the store can see, in every family. An in-process store sees
    /// every tenant; a store kept in each tenant's schema sees the current tenant, where that user lives.
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
/// <param name="UserId">Owner user identifier, when consumed or reused.</param>
/// <param name="TenantId">Tenant bound to the token, when consumed or reused.</param>
/// <param name="FamilyId">Family of the token, when consumed or reused. Callers decide by <c>Status</c> (or
/// <c>Succeeded</c>), never by the presence of these values.</param>
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
