using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Options;

/// <summary>
/// Fails <see cref="PinotechrdSecurityOptions"/> validation when nothing makes the library rely on tenant membership.
/// The setup counts as proving membership only when all three hold: <typeparamref name="TContext"/> derives from
/// <see cref="PinotechrdSecurityDbContext{TUser, TRole}"/>; its registered <c>DbContextOptions&lt;TContext&gt;</c>
/// were built with <c>UsePinotechrdSecurity()</c>; and, in <see cref="TenantSchemaMode.SearchPath"/>,
/// <c>ApplicationTakesResponsibilityForSearchPath</c> is <see langword="false"/>. Otherwise an
/// <see cref="IIdentityValidator{TUser}"/> must be registered, or
/// <see cref="PinotechrdSecurityOptions.AllowUnverifiedTenantMembership"/> set.
/// </summary>
/// <remarks>
/// <para>
/// The check cannot see the database provider: a provider that ignores schemas (for example SQLite or InMemory on
/// one shared database) puts every tenant's users in the same tables unless each tenant has its own database.
/// </para>
/// <para>
/// When the registered options cannot be built without a tenant (for example scoped options that pick the tenant's
/// own database role and throw when no tenant is resolved), the start is not failed and the deferral is logged. The
/// same check also runs at the start of every sign-in, two-factor completion and refresh, against the context the
/// users are read from (<see cref="TenantMembership.ThrowIfNotProven"/>), so it covers that case and options that
/// differ per tenant.
/// </para>
/// </remarks>
internal sealed class TenantMembershipValidator<TContext, TUser> : IValidateOptions<PinotechrdSecurityOptions>
    where TContext : DbContext
    where TUser : class
{
    private static readonly Action<ILogger, string, string, Exception?> LogDeferred = LoggerMessage.Define<string, string>(
        LogLevel.Information,
        new EventId(4103, "TenantMembershipCheckDeferred"),
        "The options of {Context} cannot be built without a request ({Error}); tenant membership is checked when a token is issued instead.");

    private readonly IServiceProviderIsService _serviceProviderIsService;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger? _logger;
    private int _deferralLogged;

    public TenantMembershipValidator(IServiceProviderIsService serviceProviderIsService, IServiceScopeFactory scopeFactory, ILoggerFactory? loggerFactory = null)
    {
        _serviceProviderIsService = serviceProviderIsService;
        _scopeFactory = scopeFactory;
        _logger = loggerFactory?.CreateLogger("Pinotechrd.Security.TenantMembership");
    }

    public ValidateOptionsResult Validate(string? name, PinotechrdSecurityOptions options)
    {
        if (options.AllowUnverifiedTenantMembership
            || _serviceProviderIsService.IsService(typeof(IIdentityValidator<TUser>)))
        {
            return ValidateOptionsResult.Success;
        }

        var reason = FindReasonMembershipIsNotProven();
        if (reason is null)
        {
            return ValidateOptionsResult.Success;
        }

        return ValidateOptionsResult.Fail(TenantMembership.Message(typeof(TContext), typeof(TUser).Name, reason));
    }

    private string? FindReasonMembershipIsNotProven()
    {
        if (!TenantMembership.DerivesFromSecurityContext(typeof(TContext)))
        {
            return TenantMembership.NotDerived;
        }

        using var scope = _scopeFactory.CreateScope();
        DbContextOptions<TContext>? contextOptions;
        try
        {
            contextOptions = scope.ServiceProvider.GetService<DbContextOptions<TContext>>();
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            // The options depend on the request (typically the tenant's own connection string) and cannot be built
            // here. The check runs against the request's context before tokens are issued instead.
            // The options are validated more than once at start; the deferral is logged once.
            if (_logger != null && Interlocked.Exchange(ref _deferralLogged, 1) == 0)
            {
                LogDeferred(_logger, typeof(TContext).Name, e.GetType().Name + ": " + e.Message, null);
            }
            return null;
        }

        if (contextOptions is null)
        {
            return $"no DbContextOptions<{typeof(TContext).Name}> is registered, so its settings cannot be read.";
        }

        return TenantMembership.SettingsReason(contextOptions);
    }
}

/// <summary>
/// Whether a context's setup proves tenant membership: the reasons shared by the start-up check and the check made
/// before tokens are issued.
/// </summary>
internal static class TenantMembership
{
    public const string NotDerived = "it does not derive from PinotechrdSecurityDbContext<TUser, TRole>.";

    public static bool DerivesFromSecurityContext(Type type)
    {
        for (var current = type.BaseType; current is not null; current = current.BaseType)
        {
            if (current.IsGenericType && current.GetGenericTypeDefinition() == typeof(PinotechrdSecurityDbContext<,>))
            {
                return true;
            }
        }

        return false;
    }

    public static string? SettingsReason(IDbContextOptions options)
    {
        var settings = options.FindExtension<PinotechrdSecurityDbContextOptionsExtension>()?.Settings;
        if (settings is null)
        {
            return "its options are not configured with UsePinotechrdSecurity().";
        }

        if (settings.TenantSchemaMode == TenantSchemaMode.SearchPath && settings.ApplicationTakesResponsibilityForSearchPath)
        {
            return "it uses TenantSchemaMode.SearchPath with ApplicationTakesResponsibilityForSearchPath, so the library " +
                   "does not bind connections to the tenant's schema.";
        }

        return null;
    }

    public static string Message(Type contextType, string userTypeName, string reason) =>
        $"Tenant membership cannot be verified for {contextType.FullName}: {reason} Finding a user therefore " +
        $"does not prove the user belongs to the resolved tenant. Register an IIdentityValidator<{userTypeName}> " +
        "that checks membership, or set PinotechrdSecurityOptions.AllowUnverifiedTenantMembership to true if the " +
        "application checks it elsewhere.";

    /// <summary>
    /// The check against the request's own context, made before any token is issued: it covers registrations whose
    /// options could not be read when the host started.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context's setup does not prove membership.</exception>
    public static void ThrowIfNotProven(DbContext context, string userTypeName)
    {
        var type = context.GetType();
        var reason = DerivesFromSecurityContext(type)
            ? SettingsReason(context.GetService<IDbContextOptions>())
            : NotDerived;
        if (reason is not null)
        {
            throw new InvalidOperationException(Message(type, userTypeName, reason));
        }
    }
}
