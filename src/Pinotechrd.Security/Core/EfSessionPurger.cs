using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Purges the tables of <see cref="EfRefreshTokenStore{TContext}"/> and <see cref="EfTwoFactorAttemptStore{TContext}"/>
/// in the tenant schema of the scoped context.
/// </summary>
/// <remarks>
/// <para>
/// Every step is one <c>DELETE</c> (<c>ExecuteDelete</c>) whose cutoff, <c>now - margin</c>, comes from the injected
/// <see cref="TimeProvider"/> and is sent as a parameter, as the stores do. No transaction is opened or required; inside
/// the caller's transaction, if any, the steps run in it.
/// </para>
/// <para>
/// Order and concurrency with live traffic:
/// </para>
/// <list type="number">
/// <item>Tokens of every family with no token whose <c>expires_at</c> is after the cutoff. A family with a live token
/// keeps all its tokens, consumed ones included, so their replay is still reuse. A refresh can only add a token to a
/// family after consuming a live token of it, and that token keeps the family for at least the margin. A token
/// inserted while the <c>DELETE</c> runs is not in its snapshot and is not deleted.</item>
/// <item>Family rows with no token left. Runs after the tokens, so a revoked family is deleted only once all its tokens
/// are gone. A token saved into a family after its last token was purged would need a refresh that consumed a token
/// of that family more than the margin earlier; with any shorter gap, that token still keeps the family.</item>
/// <item>Two-factor attempts whose <c>expires_at</c> is before the cutoff: their token expired more than the margin
/// ago, so no instance still counts attempts for it, unless its clock is behind by more than the margin.</item>
/// </list>
/// <para>
/// A purge interrupted between steps leaves only rows the next purge deletes (family rows without tokens).
/// </para>
/// </remarks>
/// <typeparam name="TContext">Context whose model maps the refresh token tables, the two-factor attempt table, or both.</typeparam>
internal sealed class EfSessionPurger<TContext> : IPinotechrdSessionPurger
    where TContext : DbContext
{
    private readonly TContext _context;
    private readonly TimeProvider _timeProvider;

    public EfSessionPurger(TContext context, TimeProvider? timeProvider = null)
    {
        _context = context;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public async Task<SessionPurgeResult> PurgeExpiredAsync(TimeSpan? margin = null, CancellationToken cancellationToken = default)
    {
        var keep = margin ?? IPinotechrdSessionPurger.DefaultMargin;
        ArgumentOutOfRangeException.ThrowIfLessThan(keep, IPinotechrdSessionPurger.MinimumMargin, nameof(margin));

        var mapsTokens = IsMapped<RefreshTokenRecord>() && IsMapped<RefreshTokenFamilyRecord>();
        var mapsAttempts = IsMapped<TwoFactorAttemptRecord>();
        if (!mapsTokens && !mapsAttempts)
        {
            throw new InvalidOperationException(
                $"{typeof(TContext).Name} maps no table to purge. Set MapRefreshTokens = true or MapTwoFactorAttempts = true " +
                "in UsePinotechrdSecurity(o => ...), add a migration, and apply it to every tenant schema.");
        }

        var cutoff = _timeProvider.GetUtcNow().UtcDateTime - keep;
        int tokens = 0, families = 0, attempts = 0;

        if (mapsTokens)
        {
            var tokenSet = _context.Set<RefreshTokenRecord>();
            tokens = await tokenSet
                .Where(t => !tokenSet.Any(o => o.FamilyId == t.FamilyId && o.ExpiresAt > cutoff))
                .ExecuteDeleteAsync(cancellationToken);

            families = await _context.Set<RefreshTokenFamilyRecord>()
                .Where(f => !tokenSet.Any(t => t.FamilyId == f.FamilyId))
                .ExecuteDeleteAsync(cancellationToken);
        }

        if (mapsAttempts)
        {
            attempts = await _context.Set<TwoFactorAttemptRecord>()
                .Where(a => a.ExpiresAt < cutoff)
                .ExecuteDeleteAsync(cancellationToken);
        }

        return new SessionPurgeResult(tokens, families, attempts);
    }

    private bool IsMapped<T>() => _context.Model.FindEntityType(typeof(T)) != null;
}
