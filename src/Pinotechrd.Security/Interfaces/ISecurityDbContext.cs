using Pinotechrd.Security.Entities;

namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Defines the contract for a database context capable of providing security-related entities.
/// </summary>
public interface ISecurityDbContext
{
    /// <summary>
    /// Gets the set of security permissions.
    /// </summary>
    IQueryable<SecurityPermission> Permissions { get; }

    /// <summary>
    /// Gets the set of security modules.
    /// </summary>
    IQueryable<SecurityModule> Modules { get; }

    /// <summary>
    /// Gets the set of system subscriptions.
    /// </summary>
    IQueryable<SystemSubscription> SystemSubscriptions { get; }

    /// <summary>
    /// Gets the mapping between roles and permissions.
    /// </summary>
    IQueryable<RolePermission> RolePermissions { get; }

    /// <summary>
    /// Gets the per-user Allow and Deny overrides.
    /// </summary>
    IQueryable<UserModulePermission> UserModulePermissions { get; }

    /// <summary>
    /// Gets the mapping between subscription plans and authorized modules.
    /// </summary>
    IQueryable<SubscriptionPlanModule> SubscriptionPlanModules { get; }

    /// <summary>
    /// Saves all changes made in this context to the database.
    /// </summary>
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
