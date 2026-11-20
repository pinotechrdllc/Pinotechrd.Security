using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;
using Pinotechrd.Security.Tests.Data;
using Xunit;

namespace Pinotechrd.Security.Tests.Hosting;

/// <summary>
/// Outside Development, <c>AddPinotechrdSecurity</c> refuses to start with in-memory session stores or unpersisted Data
/// Protection keys unless each is allowed, reports every problem at once, and logs a warning for what is allowed.
/// </summary>
public class DurableStateCheckTests : IDisposable
{
    private const string Secret = "durable-state-check-secret-of-32-bytes!!";
    private readonly string _keys = Path.Combine(Path.GetTempPath(), "pinotechrd-durable-check-" + Guid.NewGuid().ToString("N"));

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

    private sealed class Setup
    {
        public string Environment { get; init; } = "Production";
        public bool PersistKeys { get; init; } = true;
        public bool DurableStores { get; init; }
        public Action<IServiceCollection>? Before { get; init; }
        public Action<IServiceCollection>? After { get; init; }
        public Action<PinotechrdSecurityOptions>? Configure { get; init; }
        public Action<IConfigurationBuilder>? Configuration { get; init; }
    }

    private async Task<Entry[]> StartAsync(Setup setup)
    {
        var logs = new CapturingProvider();
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = setup.Environment });
        builder.Logging.ClearProviders();
        builder.Logging.SetMinimumLevel(LogLevel.Trace);
        builder.Logging.AddProvider(logs);
        setup.Configuration?.Invoke(builder.Configuration);
        // Development would validate every registration; the services the stores need at request time are not here.
        builder.ConfigureContainer(new DefaultServiceProviderFactory(new ServiceProviderOptions { ValidateOnBuild = false, ValidateScopes = false }));
        if (setup.PersistKeys)
        {
            builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(_keys)).SetApplicationName("durable-check-tests");
        }

        builder.Services.AddDbContext<SecDb>(o => o.UseSqlite("Data Source=:memory:"));
        setup.Before?.Invoke(builder.Services);
        builder.Services.AddPinotechrdSecurity<SecDb, HostUser, HostRole>(o =>
        {
            o.Jwt.Secret = Secret;
            o.Jwt.Issuer = "iss";
            o.Jwt.Audience = "aud";
            o.AllowUnverifiedTenantMembership = true;
            setup.Configure?.Invoke(o);
        });
        if (setup.DurableStores) builder.Services.AddPinotechrdEfRefreshTokenStore<SecDb>().AddPinotechrdEfTwoFactorAttemptStore<SecDb>();
        setup.After?.Invoke(builder.Services);

        using var host = builder.Build();
        await host.StartAsync();
        await host.StopAsync();
        return logs.Entries;
    }

    private async Task<string> FailureAsync(Setup setup)
    {
        var act = () => StartAsync(setup);
        return (await act.Should().ThrowAsync<InvalidOperationException>()).Which.Message;
    }

    // ---- Stores ------------------------------------------------------------------------------------

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Testing")]
    public async Task OutsideDevelopment_TheDefaultStores_ShouldFailTheStart_NamingBothStoresAndTheOptOut(string environment)
    {
        var message = await FailureAsync(new Setup { Environment = environment });

        message.Should().Contain(environment)
            .And.Contain("IRefreshTokenStore").And.Contain("AddPinotechrdEfRefreshTokenStore")
            .And.Contain("ITwoFactorAttemptStore").And.Contain("AddPinotechrdEfTwoFactorAttemptStore")
            .And.Contain("AllowInMemoryStores")
            .And.NotContain("Data Protection");
    }

    [Fact]
    public async Task InDevelopment_NothingShouldBeChecked()
    {
        var entries = await StartAsync(new Setup { Environment = "Development", PersistKeys = false });

        entries.Should().NotContain(e => e.EventId.Id == 4101 || e.EventId.Id == 4102);
    }

    [Fact]
    public async Task DurableStores_ShouldStart_WithoutAWarning()
    {
        var entries = await StartAsync(new Setup { DurableStores = true });

        entries.Should().NotContain(e => e.EventId.Id == 4101 || e.EventId.Id == 4102);
    }

    [Fact]
    public async Task DurableStores_RegisteredBeforeAddPinotechrdSecurity_ShouldStart()
    {
        var act = () => StartAsync(new Setup { Before = s => s.AddPinotechrdEfRefreshTokenStore<SecDb>().AddPinotechrdEfTwoFactorAttemptStore<SecDb>() });

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task AllowedInMemoryStores_ShouldStart_AndLogWarning4102()
    {
        var entries = await StartAsync(new Setup { Configure = o => o.AllowInMemoryStores = true });

        var warning = entries.Should().ContainSingle(e => e.EventId.Id == 4102).Subject;
        warning.Level.Should().Be(LogLevel.Warning);
        warning.EventId.Should().Be(DurableStateCheck.InMemoryStoresInUse);
        warning.Message.Should().Contain("IRefreshTokenStore, ITwoFactorAttemptStore");
    }

    [Fact]
    public async Task OnlyOneDurableStore_ShouldStillFail_NamingTheOther()
    {
        var message = await FailureAsync(new Setup { After = s => s.AddPinotechrdEfRefreshTokenStore<SecDb>() });

        message.Should().Contain("ITwoFactorAttemptStore is the in-memory store").And.NotContain("IRefreshTokenStore is the in-memory store");
    }

    [Fact]
    public async Task AKeyedRegistrationAddedLast_ShouldNotHideTheInMemoryStore()
    {
        var message = await FailureAsync(new Setup
        {
            After = s =>
            {
                s.AddPinotechrdEfTwoFactorAttemptStore<SecDb>();
                s.AddKeyedSingleton<IRefreshTokenStore>("audit", (_, _) => NSubstitute.Substitute.For<IRefreshTokenStore>());
            },
        });

        message.Should().Contain("IRefreshTokenStore is the in-memory store");
    }

    private sealed class DerivedStore : InMemoryRefreshTokenStore;

    [Fact]
    public async Task ASubclassOfTheInMemoryStore_ShouldCountAsInMemory()
    {
        var message = await FailureAsync(new Setup
        {
            After = s => s.Replace(ServiceDescriptor.Singleton<IRefreshTokenStore, DerivedStore>()).AddPinotechrdEfTwoFactorAttemptStore<SecDb>(),
        });

        message.Should().Contain("IRefreshTokenStore is the in-memory store");
    }

    [Fact]
    public async Task OwnStoresRegisteredWithAFactory_ShouldBeTrustedAsTheApplicationsOwn()
    {
        var act = () => StartAsync(new Setup
        {
            After = s =>
            {
                s.AddSingleton<IRefreshTokenStore>(_ => NSubstitute.Substitute.For<IRefreshTokenStore>());
                s.AddSingleton<ITwoFactorAttemptStore>(_ => NSubstitute.Substitute.For<ITwoFactorAttemptStore>());
            },
        });

        await act.Should().NotThrowAsync();
    }

    // ---- Data Protection keys -----------------------------------------------------------------------

    [Fact]
    public async Task UnpersistedKeys_ShouldFailTheStart_NamingTheFixAndTheOptOut()
    {
        var message = await FailureAsync(new Setup { PersistKeys = false, DurableStores = true });

        message.Should().Contain("PersistKeysTo").And.Contain("AllowUnpersistedDataProtectionKeys").And.NotContain("in-memory store");
    }

    [Fact]
    public async Task AllowedUnpersistedKeys_ShouldStart_AndLogWarning4101()
    {
        var entries = await StartAsync(new Setup { PersistKeys = false, DurableStores = true, Configure = o => o.AllowUnpersistedDataProtectionKeys = true });

        var warning = entries.Should().ContainSingle(e => e.EventId.Id == 4101).Subject;
        warning.Level.Should().Be(LogLevel.Warning);
        warning.EventId.Should().Be(DurableStateCheck.KeysNotPersisted);
        warning.Message.Should().StartWith("No Data Protection key repository is configured");
    }

    [Fact]
    public async Task BothProblems_ShouldBeReportedInOneFailure()
    {
        var message = await FailureAsync(new Setup { PersistKeys = false });

        message.Should().Contain("PersistKeysTo").And.Contain("IRefreshTokenStore is the in-memory store").And.Contain("ITwoFactorAttemptStore is the in-memory store");
    }

    // ---- Where the opt-outs come from ----------------------------------------------------------------

    [Fact]
    public async Task OptOuts_SetWithConfigureBeforeAddPinotechrdSecurity_ShouldBeKept()
    {
        var act = () => StartAsync(new Setup
        {
            PersistKeys = false,
            Before = s => s.Configure<PinotechrdSecurityOptions>(o =>
            {
                o.AllowInMemoryStores = true;
                o.AllowUnpersistedDataProtectionKeys = true;
            }),
        });

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task OptOuts_BoundFromConfigurationAfterAddPinotechrdSecurity_ShouldApply()
    {
        var act = () => StartAsync(new Setup
        {
            PersistKeys = false,
            Configuration = c => c.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Security:AllowInMemoryStores"] = "true",
                ["Security:AllowUnpersistedDataProtectionKeys"] = "true",
            }),
            After = s => s.AddOptions<PinotechrdSecurityOptions>().BindConfiguration("Security"),
        });

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task ASecondAddPinotechrdSecurityCall_ShouldNotResetAnOptOut_AndShouldNotAddASecondCheck()
    {
        var act = () => StartAsync(new Setup
        {
            Configure = o => o.AllowInMemoryStores = true,
            After = s =>
            {
                s.AddPinotechrdSecurity<SecDb, HostUser, HostRole>(o =>
                {
                    o.Jwt.Secret = Secret;
                    o.Jwt.Issuer = "iss";
                    o.Jwt.Audience = "aud";
                    o.AllowUnverifiedTenantMembership = true;
                });
                s.Count(d => d.ServiceType == typeof(IHostedService) && d.ImplementationType == typeof(DurableStateCheck)).Should().Be(1);
            },
        });

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public void EventIds_ShouldBeStable()
    {
        DurableStateCheck.KeysNotPersisted.Id.Should().Be(4101);
        DurableStateCheck.InMemoryStoresInUse.Id.Should().Be(4102);
    }
}
