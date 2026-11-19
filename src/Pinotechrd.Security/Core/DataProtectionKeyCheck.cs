using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Warns at startup, outside Development, when the Data Protection keys are not persisted to an explicit
/// repository. Two-factor tokens are protected with those keys: with the default key storage a token issued by
/// one instance cannot be read by another, nor after a restart where the key folder is not kept (containers).
/// Startup is not stopped.
/// </summary>
internal sealed class DataProtectionKeyCheck : IHostedService
{
    /// <summary>Event logged when the keys are not persisted.</summary>
    public static readonly EventId KeysNotPersisted = new(4101, "DataProtectionKeysNotPersisted");

    private static readonly Action<ILogger, Exception?> LogKeysNotPersisted = LoggerMessage.Define(
        LogLevel.Warning,
        KeysNotPersisted,
        "No Data Protection key repository is configured, so keys may not be shared: two-factor tokens can fail on another instance or " +
        "after a restart. Call AddDataProtection().PersistKeysTo...() with storage every instance shares, and SetApplicationName(...).");

    private readonly IOptions<KeyManagementOptions> _keyManagement;
    private readonly IHostEnvironment _environment;
    private readonly ILogger<DataProtectionKeyCheck> _logger;

    public DataProtectionKeyCheck(
        IOptions<KeyManagementOptions> keyManagement,
        IHostEnvironment environment,
        ILogger<DataProtectionKeyCheck> logger)
    {
        _keyManagement = keyManagement;
        _environment = environment;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        // A null repository means no PersistKeysTo* call: Data Protection then falls back to a per-machine folder,
        // the registry, or memory, none of which is shared between instances.
        if (!_environment.IsDevelopment() && _keyManagement.Value.XmlRepository == null)
        {
            LogKeysNotPersisted(_logger, null);
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
