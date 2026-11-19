using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
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
/// The check cannot see the database provider: a provider that ignores schemas (for example SQLite or InMemory on
/// one shared database) puts every tenant's users in the same tables unless each tenant has its own database.
/// </remarks>
internal sealed class TenantMembershipValidator<TContext, TUser> : IValidateOptions<PinotechrdSecurityOptions>
    where TContext : DbContext
    where TUser : class
{
    private readonly IServiceProviderIsService _serviceProviderIsService;
    private readonly IServiceScopeFactory _scopeFactory;

    public TenantMembershipValidator(IServiceProviderIsService serviceProviderIsService, IServiceScopeFactory scopeFactory)
    {
        _serviceProviderIsService = serviceProviderIsService;
        _scopeFactory = scopeFactory;
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

        return ValidateOptionsResult.Fail(
            $"Tenant membership cannot be verified for {typeof(TContext).FullName}: {reason} Finding a user therefore " +
            $"does not prove the user belongs to the resolved tenant. Register an IIdentityValidator<{typeof(TUser).Name}> " +
            "that checks membership, or set PinotechrdSecurityOptions.AllowUnverifiedTenantMembership to true if the " +
            "application checks it elsewhere.");
    }

    private string? FindReasonMembershipIsNotProven()
    {
        if (!DerivesFromSecurityContext(typeof(TContext)))
        {
            return "it does not derive from PinotechrdSecurityDbContext<TUser, TRole>.";
        }

        using var scope = _scopeFactory.CreateScope();
        var contextOptions = scope.ServiceProvider.GetService<DbContextOptions<TContext>>();
        if (contextOptions is null)
        {
            return $"no DbContextOptions<{typeof(TContext).Name}> is registered, so its settings cannot be read.";
        }

        var settings = contextOptions.FindExtension<PinotechrdSecurityDbContextOptionsExtension>()?.Settings;
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

    private static bool DerivesFromSecurityContext(Type type)
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
}
