using System.Threading;

namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Counts verification attempts per two-factor challenge, so a two-factor token allows only a few code guesses.
/// </summary>
/// <remarks>
/// The default registration keeps the counts in memory. With several instances, register an implementation
/// backed by shared storage, or each instance allows its own attempts for the same token.
/// </remarks>
public interface ITwoFactorAttemptStore
{
    /// <summary>
    /// Atomically counts one attempt for a challenge and returns the number of attempts including this one.
    /// </summary>
    /// <param name="challengeId">Random identifier of the two-factor token.</param>
    /// <param name="expiresAt">When the challenge expires; the count may be dropped after it.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<int> RegisterAttemptAsync(string challengeId, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks a challenge as having used all its attempts: every later <see cref="RegisterAttemptAsync"/> for it
    /// must return <see cref="int.MaxValue"/>. Used when a failed attempt could not be recorded elsewhere.
    /// </summary>
    /// <param name="challengeId">Random identifier of the two-factor token.</param>
    /// <param name="expiresAt">When the challenge expires; the mark may be dropped after it.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task ExhaustAsync(string challengeId, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);
}
