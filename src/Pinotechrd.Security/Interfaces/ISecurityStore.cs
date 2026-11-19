using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Models;

namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// High-level store for security-related metadata.
/// Provides a layer of abstraction over the raw database for caching and optimization.
/// </summary>
public interface ISecurityStore
{
    /// <summary>
    /// Validates if the tenant has an active subscription.
    /// </summary>
    Task<bool> IsSubscriptionActiveAsync(string tenantId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates if a specific module is active for the tenant.
    /// </summary>
    Task<bool> IsModuleActiveAsync(string tenantId, string moduleCode, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets all active module codes for the specified tenant based on their subscription.
    /// </summary>
    Task<IEnumerable<string>> GetActiveModuleCodesAsync(string tenantId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Modules on the tenant's active plan, with their active permissions attached.
    /// </summary>
    Task<IReadOnlyList<SecurityModule>> GetActiveCatalogAsync(string tenantId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Allow and Deny overrides for one user. Empty when the id is not a guid.
    /// </summary>
    Task<IReadOnlyList<UserPermissionOverride>> GetUserOverridesAsync(string userId, CancellationToken cancellationToken = default);
}
