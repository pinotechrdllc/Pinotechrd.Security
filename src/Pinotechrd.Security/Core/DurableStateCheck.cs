using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;

namespace Pinotechrd.Security.Core;

/// <summary>
/// The service registrations as <c>AddPinotechrdSecurity</c> left them, read again when the host starts, after every
/// later registration (for example a persistent store added after the call).
/// </summary>
internal sealed class SecurityServiceRegistrations(IServiceCollection services)
{
    /// <summary>
    /// The implementation type of the last unkeyed registration of <typeparamref name="TService"/>, the one the
    /// container resolves; <see langword="null"/> for a factory registration or when there is none.
    /// </summary>
    public Type? LastImplementationOf<TService>()
    {
        var descriptor = services.LastOrDefault(d => d.ServiceType == typeof(TService) && !d.IsKeyedService);
        if (descriptor == null) return null;
        return descriptor.ImplementationType ?? descriptor.ImplementationInstance?.GetType();
    }
}

/// <summary>
/// Outside Development, stops the host before any hosted service starts when session state would not survive a
/// restart or be shared between instances: the in-memory refresh token or two-factor attempt store is the registered
/// store, or no Data Protection key repository is configured. Every problem is reported in one exception. Each can be
/// allowed (<see cref="PinotechrdSecurityOptions.AllowInMemoryStores"/>,
/// <see cref="PinotechrdSecurityOptions.AllowUnpersistedDataProtectionKeys"/>); an allowed one is logged as a warning.
/// </summary>
/// <remarks>
/// The stores are recognised from the service registrations: a factory, decorator or keyed registration, or a
/// registration made outside <see cref="IServiceCollection"/> (another container), is trusted as the application's own.
/// </remarks>
internal sealed class DurableStateCheck : IHostedLifecycleService
{
    /// <summary>Event logged when the keys are not persisted and that is allowed.</summary>
    public static readonly EventId KeysNotPersisted = new(4101, "DataProtectionKeysNotPersisted");

    /// <summary>Event logged when an in-memory store is in use outside Development and that is allowed.</summary>
    public static readonly EventId InMemoryStoresInUse = new(4102, "InMemorySessionStoresInUse");

    private const string KeysAdvice =
        "Call AddDataProtection().PersistKeysTo...() with storage every instance shares, and SetApplicationName(...)";

    private static readonly Action<ILogger, Exception?> LogKeysNotPersisted = LoggerMessage.Define(
        LogLevel.Warning,
        KeysNotPersisted,
        "No Data Protection key repository is configured, so keys may not be shared: two-factor tokens can fail on another instance or " +
        "after a restart. " + KeysAdvice + ".");

    private static readonly Action<ILogger, string, Exception?> LogInMemoryStores = LoggerMessage.Define<string>(
        LogLevel.Warning,
        InMemoryStoresInUse,
        "In-memory session stores are in use outside Development ({Stores}): sessions are per instance and lost on restart.");

    private readonly IOptions<KeyManagementOptions> _keyManagement;
    private readonly IHostEnvironment _environment;
    private readonly ILogger<DurableStateCheck> _logger;
    private readonly IOptions<PinotechrdSecurityOptions> _security;
    private readonly SecurityServiceRegistrations _registrations;

    public DurableStateCheck(
        IOptions<KeyManagementOptions> keyManagement,
        IHostEnvironment environment,
        ILogger<DurableStateCheck> logger,
        IOptions<PinotechrdSecurityOptions> security,
        SecurityServiceRegistrations registrations)
    {
        _keyManagement = keyManagement;
        _environment = environment;
        _logger = logger;
        _security = security;
        _registrations = registrations;
    }

    /// <summary>Runs after options validation and before any hosted service's <c>StartAsync</c>.</summary>
    public Task StartingAsync(CancellationToken cancellationToken)
    {
        if (_environment.IsDevelopment()) return Task.CompletedTask;

        var security = _security.Value;
        var problems = new List<string>();

        // A null repository means no PersistKeysTo* call: Data Protection then falls back to a per-machine folder,
        // the registry, or memory, none of which is shared between instances.
        if (_keyManagement.Value.XmlRepository == null)
        {
            if (security.AllowUnpersistedDataProtectionKeys) LogKeysNotPersisted(_logger, null);
            else problems.Add(
                "No Data Protection key repository is configured: two-factor tokens would fail on another instance or after a restart. " +
                KeysAdvice + ", or set PinotechrdSecurityOptions.AllowUnpersistedDataProtectionKeys when the default key folder is " +
                "already shared (for example Azure App Service) or there is a single instance whose key folder survives restarts.");
        }

        var stores = new List<string>();
        if (IsInMemory<IRefreshTokenStore, InMemoryRefreshTokenStore>()) stores.Add(nameof(IRefreshTokenStore));
        if (IsInMemory<ITwoFactorAttemptStore, InMemoryTwoFactorAttemptStore>()) stores.Add(nameof(ITwoFactorAttemptStore));
        if (stores.Count > 0)
        {
            if (security.AllowInMemoryStores) LogInMemoryStores(_logger, string.Join(", ", stores), null);
            else problems.Add(
                "In-memory session stores are in use, which are per instance and lost on restart: " +
                string.Join(" ", stores.Select(Advice)) +
                " Set PinotechrdSecurityOptions.AllowInMemoryStores only for a single instance whose sessions may be lost.");
        }

        if (problems.Count > 0)
        {
            throw new InvalidOperationException(
                $"Session state is not durable outside Development (environment '{_environment.EnvironmentName}'). " + string.Join(" ", problems));
        }

        return Task.CompletedTask;
    }

    private bool IsInMemory<TService, TInMemory>() =>
        _registrations.LastImplementationOf<TService>() is { } type && type.IsAssignableTo(typeof(TInMemory));

    private static string Advice(string store) => store == nameof(IRefreshTokenStore)
        ? "IRefreshTokenStore is the in-memory store: call AddPinotechrdEfRefreshTokenStore<TContext>() or register your own."
        : "ITwoFactorAttemptStore is the in-memory store: call AddPinotechrdEfTwoFactorAttemptStore<TContext>() or register your own.";

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StoppingAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
