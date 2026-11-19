using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pinotechrd.Security.Core;
using Xunit;

namespace Pinotechrd.Security.Tests.Hosting;

/// <summary>
/// The startup check that warns when Data Protection keys are not persisted (two-factor tokens cannot be read by another
/// instance or after a restart). Logs are captured with a small provider; no logging package is added.
/// </summary>
public class DataProtectionKeyCheckTests : IDisposable
{
    private const int KeysNotPersistedEventId = 4101;

    private readonly string _keys = Path.Combine(Path.GetTempPath(), "pinotechrd-dp-check-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_keys, recursive: true); } catch (IOException) { }
    }

    private sealed record Entry(LogLevel Level, EventId EventId, string Message);

    private sealed class CapturingProvider : ILoggerProvider
    {
        private readonly List<Entry> _entries = [];

        public Entry[] Entries
        {
            get { lock (_entries) return _entries.ToArray(); }
        }

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(CapturingProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                lock (owner._entries) owner._entries.Add(new Entry(logLevel, eventId, formatter(state, exception)));
            }
        }
    }

    /// <summary>Starts a generic host with only the check as hosted service, in the given environment.</summary>
    private static async Task<Entry[]> RunAsync(string environment, Action<IDataProtectionBuilder>? configureKeys)
    {
        var logs = new CapturingProvider();
        using var host = Host.CreateDefaultBuilder()
            .UseEnvironment(environment)
            .ConfigureLogging(logging =>
            {
                logging.ClearProviders();
                logging.SetMinimumLevel(LogLevel.Trace);
                logging.AddProvider(logs);
            })
            .ConfigureServices(services =>
            {
                var builder = services.AddDataProtection();
                configureKeys?.Invoke(builder);
                services.AddHostedService(sp => new DataProtectionKeyCheck(
                    sp.GetRequiredService<IOptions<KeyManagementOptions>>(),
                    sp.GetRequiredService<IHostEnvironment>(),
                    sp.GetRequiredService<ILogger<DataProtectionKeyCheck>>()));
            })
            .Build();

        await host.StartAsync();
        await host.StopAsync();
        return logs.Entries;
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public async Task StartAsync_ShouldLogAWarningWithEvent4101_WhenKeysAreNotPersistedOutsideDevelopment(string environment)
    {
        var entries = await RunAsync(environment, configureKeys: null);

        var warning = entries.Should().ContainSingle(e => e.EventId.Id == KeysNotPersistedEventId).Subject;
        warning.Level.Should().Be(LogLevel.Warning);
        warning.EventId.Should().Be(DataProtectionKeyCheck.KeysNotPersisted);
        warning.Message.Should().StartWith("No Data Protection key repository is configured");
    }

    [Fact]
    public async Task StartAsync_ShouldNotLog_WhenTheEnvironmentIsDevelopment()
    {
        var entries = await RunAsync("Development", configureKeys: null);

        entries.Should().NotContain(e => e.EventId.Id == KeysNotPersistedEventId);
    }

    [Fact]
    public async Task StartAsync_ShouldNotLog_WhenKeysArePersistedToTheFileSystem()
    {
        var entries = await RunAsync("Production", b => b.PersistKeysToFileSystem(new DirectoryInfo(_keys)).SetApplicationName("dp-check-tests"));

        entries.Should().NotContain(e => e.EventId.Id == KeysNotPersistedEventId);
    }

    [Fact]
    public async Task StartAsync_ShouldNotStopTheHost_WhenKeysAreNotPersisted()
    {
        var act = () => RunAsync("Production", configureKeys: null);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public void KeysNotPersisted_ShouldHaveEventId4101()
    {
        DataProtectionKeyCheck.KeysNotPersisted.Id.Should().Be(KeysNotPersistedEventId);
    }

    [Fact]
    public async Task AddPinotechrdSecurity_ShouldRegisterTheCheck_SoAProductionHostWithoutPersistedKeysWarns()
    {
        var logs = new CapturingProvider();
        await using var api = await TenantDatabaseApi.StartAsync(
            new Dictionary<string, string[]> { ["a"] = [] },
            configureBuilder: builder => builder.Logging.AddProvider(logs));

        logs.Entries.Should().ContainSingle(e => e.EventId.Id == KeysNotPersistedEventId && e.Level == LogLevel.Warning);
    }

    [Fact]
    public async Task AddPinotechrdSecurity_ShouldNotWarn_WhenTheApplicationPersistedItsKeys()
    {
        var logs = new CapturingProvider();
        await using var api = await TenantDatabaseApi.StartAsync(
            new Dictionary<string, string[]> { ["a"] = [] },
            configureBuilder: builder =>
            {
                builder.Logging.AddProvider(logs);
                builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(_keys)).SetApplicationName("dp-check-tests");
            });

        logs.Entries.Should().NotContain(e => e.EventId.Id == KeysNotPersistedEventId);
    }
}
