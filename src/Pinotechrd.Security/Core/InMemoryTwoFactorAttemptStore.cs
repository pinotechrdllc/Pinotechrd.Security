using System.Collections.Concurrent;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Core;

/// <summary>
/// In-memory <see cref="ITwoFactorAttemptStore"/>. Thread safe. Counts are lost on restart and are not shared
/// between instances; register a shared implementation when the application runs on several instances.
/// </summary>
public class InMemoryTwoFactorAttemptStore : ITwoFactorAttemptStore
{
    private const int PurgeThreshold = 10_000;

    private readonly ConcurrentDictionary<string, Counter> _counters = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;

    private sealed class Counter
    {
        public required DateTimeOffset ExpiresAt { get; init; }
        public int Count;
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
        if (_counters.Count > PurgeThreshold) PurgeExpired();

        var counter = _counters.GetOrAdd(challengeId, _ => new Counter { ExpiresAt = expiresAt });
        return Task.FromResult(Interlocked.Increment(ref counter.Count));
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
