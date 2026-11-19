namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Deletes expired refresh tokens and two-factor attempts kept by the EF Core stores in the current tenant's schema.
/// Registered by <c>AddPinotechrdEfRefreshTokenStore&lt;TContext&gt;()</c> and
/// <c>AddPinotechrdEfTwoFactorAttemptStore&lt;TContext&gt;()</c>.
/// </summary>
/// <remarks>
/// <para>
/// Each call purges one tenant: the schema the scoped context resolves to. Run it from a scheduled job that, for
/// every tenant, creates a scope, sets the tenant and calls <see cref="PurgeExpiredAsync"/>.
/// </para>
/// <para>
/// Only the tables mapped in the context's model are purged. It is safe to run while the application serves
/// requests, needs no transaction and does not use the change tracker.
/// </para>
/// </remarks>
public interface IPinotechrdSessionPurger
{
    /// <summary>
    /// The margin used when none is given: one hour.
    /// </summary>
    static readonly TimeSpan DefaultMargin = TimeSpan.FromHours(1);

    /// <summary>
    /// The smallest margin accepted: five minutes. A shorter margin could delete a revoked family while a refresh
    /// that consumed its last token is still saving the rotated one, which would make that token valid again.
    /// </summary>
    static readonly TimeSpan MinimumMargin = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Deletes, in the current tenant's schema, the refresh token families whose tokens all expired more than
    /// <paramref name="margin"/> ago (their tokens and their revocation row) and the two-factor attempts whose
    /// token expired more than <paramref name="margin"/> ago.
    /// </summary>
    /// <remarks>
    /// A consumed refresh token is kept while any token of its family is live, so replaying it is still detected
    /// as reuse. The margin absorbs clock differences between the instances, and keeps the attempt count of a
    /// two-factor token that some instance still considers valid: deleting it would let that token count from one
    /// again.
    /// </remarks>
    /// <param name="margin">Time past expiry a row is kept; <see langword="null"/> uses <see cref="DefaultMargin"/>.</param>
    /// <param name="cancellationToken">Cancels the purge; rows already deleted stay deleted.</param>
    /// <returns>The number of rows deleted from each table.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="margin"/> is shorter than <see cref="MinimumMargin"/>.</exception>
    /// <exception cref="InvalidOperationException">The context maps neither the refresh token nor the two-factor attempt tables.</exception>
    Task<SessionPurgeResult> PurgeExpiredAsync(TimeSpan? margin = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// Rows deleted by <see cref="IPinotechrdSessionPurger.PurgeExpiredAsync"/>. A table that is not mapped counts zero.
/// </summary>
/// <param name="RefreshTokens">Rows deleted from <c>refresh_tokens</c>.</param>
/// <param name="RefreshTokenFamilies">Rows deleted from <c>refresh_token_families</c>.</param>
/// <param name="TwoFactorAttempts">Rows deleted from <c>two_factor_attempts</c>.</param>
public sealed record SessionPurgeResult(int RefreshTokens, int RefreshTokenFamilies, int TwoFactorAttempts);
