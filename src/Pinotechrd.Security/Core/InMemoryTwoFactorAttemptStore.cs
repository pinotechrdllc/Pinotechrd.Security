using System.Collections.Concurrent;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Core;

/// <summary>
/// In-memory <see cref="ITwoFactorAttemptStore"/>. Thread safe. Counts are lost on restart and are not shared
/// between instances; register a shared implementation when the application runs on several instances.
/// </summary>
/// <remarks>
/// When more than 10,000 challenges are held, each new attempt first drops the challenges whose token has
/// expired. Live challenges are never dropped, so the store holds at most about 10,000 entries or the number
/// of tokens issued in the last five minutes (the token lifetime), whichever is larger.
/// </remarks>
public class InMemoryTwoFactorAttemptStore : ITwoFactorAttemptStore
{
    private const int PurgeThreshold = 10_000;

    private readonly ConcurrentDictionary<string, Counter> _counters = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;

    private sealed class Counter
    {
        public required DateTimeOffset ExpiresAt { get; init; }
        public int Count;
        public volatile bool Exhausted;
    }

    /// <summary>
    /// Initializes the store with the system clock.
    /// </summary>
    public InMemoryTwoFactorAttemptStore() : this(TimeProvider.System)
    {
    }

    /// <summary>
    /// Initializes the store with the given clock.
    /// </summary>
    public InMemoryTwoFactorAttemptStore(TimeProvider timeProvider)
    {
        _timeProvider = timeProvider;
    }

    /// <inheritdoc />
    public Task<int> RegisterAttemptAsync(string challengeId, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        var counter = GetCounter(challengeId, expiresAt);
        var count = Interlocked.Increment(ref counter.Count);
        return Task.FromResult(counter.Exhausted ? int.MaxValue : count);
    }

    /// <inheritdoc />
    public Task ExhaustAsync(string challengeId, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        GetCounter(challengeId, expiresAt).Exhausted = true;
        return Task.CompletedTask;
    }

    private Counter GetCounter(string challengeId, DateTimeOffset expiresAt)
    {
        if (_counters.Count > PurgeThreshold) PurgeExpired();
        return _counters.GetOrAdd(challengeId, _ => new Counter { ExpiresAt = expiresAt });
    }

    private void PurgeExpired()
    {
        var now = _timeProvider.GetUtcNow();
        foreach (var (key, counter) in _counters)
        {
            if (counter.ExpiresAt <= now) _counters.TryRemove(key, out _);
        }
    }
}
