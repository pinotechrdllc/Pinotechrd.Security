namespace Pinotechrd.Security.Tests.Core;

/// <summary>
/// A <see cref="TimeProvider"/> whose clock only moves when the test advances it.
/// </summary>
internal sealed class FakeTimeProvider : TimeProvider
{
    private long _utcTicks;

    public FakeTimeProvider(DateTimeOffset? start = null)
    {
        _utcTicks = (start ?? new DateTimeOffset(2030, 1, 1, 12, 0, 0, TimeSpan.Zero)).UtcTicks;
    }

    public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref _utcTicks), TimeSpan.Zero);

    public void Advance(TimeSpan by) => Interlocked.Add(ref _utcTicks, by.Ticks);
}
