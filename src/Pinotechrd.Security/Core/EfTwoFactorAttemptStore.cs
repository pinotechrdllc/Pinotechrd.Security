using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Two-factor attempt store kept in the tenant schema through EF Core, so the attempt limit of a two-factor token
/// holds across every instance and restart. Registered by <c>AddPinotechrdEfTwoFactorAttemptStore&lt;TContext&gt;()</c>;
/// requires <see cref="PinotechrdSecurityModelOptions.MapTwoFactorAttempts"/>.
/// </summary>
/// <remarks>
/// <para>
/// Rows are keyed by the SHA-256 of the challenge id. Each attempt is one atomic <c>UPDATE ... SET count = count + 1</c>;
/// the first attempt of a challenge inserts the row, and an insert that loses the race to a concurrent one retries
/// the update. The count is then read back, so a concurrent attempt can only make the returned number larger than
/// this attempt's ordinal, never smaller: errors lean toward refusing. A failure that cannot be resolved throws.
/// </para>
/// <para>
/// The store shares the scoped context but never uses its change tracker. It throws
/// <see cref="InvalidOperationException"/> when the context has a current transaction or an ambient
/// <c>TransactionScope</c> exists, because a rollback would erase the counted attempts. Expired rows are not
/// purged; an application that deletes them must keep a margin past <c>expires_at</c> (for example one hour), since
/// a deleted row of a still-valid token starts counting again.
/// </para>
/// </remarks>
/// <typeparam name="TContext">Context whose model maps the two-factor attempt table.</typeparam>
internal sealed class EfTwoFactorAttemptStore<TContext> : ITwoFactorAttemptStore
    where TContext : DbContext
{
    private readonly TContext _context;

    public EfTwoFactorAttemptStore(TContext context)
    {
        _context = context;
    }

    /// <inheritdoc />
    public async Task<int> RegisterAttemptAsync(string challengeId, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        EnsureNoTransaction();
        var hash = RefreshTokenHash.Compute(challengeId);
        var attempts = Attempts();

        await UpsertAsync(
            hash,
            () => attempts.Where(a => a.ChallengeHash == hash)
                .ExecuteUpdateAsync(s => s.SetProperty(a => a.Count, a => a.Count + 1), cancellationToken),
            count: 1,
            exhausted: false,
            expiresAt,
            cancellationToken);

        var row = await attempts.AsNoTracking()
            .Where(a => a.ChallengeHash == hash)
            .Select(a => new { a.Count, a.Exhausted })
            .FirstOrDefaultAsync(cancellationToken);

        // A row that vanished (for example purged by the application) is treated as spent: fail closed.
        return row == null || row.Exhausted ? int.MaxValue : row.Count;
    }

    /// <inheritdoc />
    public async Task ExhaustAsync(string challengeId, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        EnsureNoTransaction();
        var hash = RefreshTokenHash.Compute(challengeId);
        var attempts = Attempts();

        await UpsertAsync(
            hash,
            () => attempts.Where(a => a.ChallengeHash == hash)
                .ExecuteUpdateAsync(s => s.SetProperty(a => a.Exhausted, true), cancellationToken),
            count: 0,
            exhausted: true,
            expiresAt,
            cancellationToken);
    }

    /// <summary>
    /// Runs <paramref name="update"/>; when no row matched, inserts one with the given values; when that insert
    /// fails because a concurrent call inserted the row first, runs the update once more.
    /// </summary>
    private async Task UpsertAsync(
        byte[] hash,
        Func<Task<int>> update,
        int count,
        bool exhausted,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        if (await update() > 0) return;

        try
        {
            await EfRawInsert.InsertAsync(
                _context,
                EntityType(),
                [
                    (nameof(TwoFactorAttemptRecord.ChallengeHash), hash),
                    (nameof(TwoFactorAttemptRecord.Count), count),
                    (nameof(TwoFactorAttemptRecord.Exhausted), exhausted),
                    (nameof(TwoFactorAttemptRecord.ExpiresAt), expiresAt.UtcDateTime)
                ],
                cancellationToken);
        }
        catch (DbException)
        {
            // Duplicate key from a concurrent first attempt: count on the row it inserted. Any other failure, or
            // an update that still matches nothing, is rethrown.
            if (await update() == 0) throw;
        }
    }

    /// <summary>
    /// Refuses to count inside a transaction: a rollback would erase the attempt and allow unlimited guesses.
    /// </summary>
    private void EnsureNoTransaction()
    {
        if (_context.Database.CurrentTransaction != null || System.Transactions.Transaction.Current != null)
        {
            throw new InvalidOperationException(
                "Two-factor attempts cannot be counted inside a transaction: a rollback would erase them and allow " +
                "unlimited guesses. Call VerifyTwoFactorCodeAsync outside any database transaction or TransactionScope.");
        }
    }

    private IQueryable<TwoFactorAttemptRecord> Attempts()
    {
        EntityType();
        return _context.Set<TwoFactorAttemptRecord>();
    }

    private IEntityType EntityType() =>
        _context.Model.FindEntityType(typeof(TwoFactorAttemptRecord))
        ?? throw new InvalidOperationException(
            $"{typeof(TContext).Name} does not map the two-factor attempt table. Set MapTwoFactorAttempts = true in " +
            "UsePinotechrdSecurity(o => o.MapTwoFactorAttempts = true), add a migration, and apply it to every tenant schema.");
}
