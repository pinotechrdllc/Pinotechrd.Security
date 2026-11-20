using Microsoft.Extensions.Logging;

namespace Pinotechrd.Security.Tests.Hosting;

/// <summary>One captured log entry, with its structured properties.</summary>
public sealed record CapturedLog(string Category, LogLevel Level, EventId EventId, string Message, IReadOnlyDictionary<string, object?> Properties)
{
    public string? Property(string name) => Properties.TryGetValue(name, out var value) ? value?.ToString() : null;
}

/// <summary>A logger provider and factory that keep every entry, for asserting on events. No logging package needed.</summary>
public sealed class CapturedLogs : ILoggerProvider, ILoggerFactory
{
    private readonly List<CapturedLog> _entries = [];

    public CapturedLog[] Entries
    {
        get { lock (_entries) return _entries.ToArray(); }
    }

    public CapturedLog[] Events(int id) => Entries.Where(e => e.EventId.Id == id).ToArray();

    public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);

    public void AddProvider(ILoggerProvider provider)
    {
    }

    public void Dispose()
    {
    }

    private sealed class Logger(CapturedLogs owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            var properties = state is IEnumerable<KeyValuePair<string, object?>> pairs
                ? pairs.Where(p => p.Key != "{OriginalFormat}").ToDictionary(p => p.Key, p => p.Value)
                : new Dictionary<string, object?>();
            lock (owner._entries) owner._entries.Add(new CapturedLog(category, logLevel, eventId, formatter(state, exception), properties));
        }
    }
}
