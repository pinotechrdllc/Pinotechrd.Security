using System.Threading;

namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Drops the cached subscription and module state of a tenant, so the next check reads it from the store.
/// </summary>
/// <remarks>
/// Call it after committing a change to a tenant's subscription, plan or modules. Every instance that shares
/// the same distributed cache reads fresh data afterwards. Changes that are not followed by an invalidation
/// (for example a subscription reaching its end date) are seen when the cached entries expire.
/// </remarks>
public interface ISecurityCacheInvalidator
{
    /// <summary>
    /// Invalidates every cached security entry of <paramref name="tenantId"/>. Other tenants are untouched.
    /// </summary>
    /// <param name="tenantId">Tenant identifier; must be a well-formed tenant identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="ArgumentException"><paramref name="tenantId"/> is not a well-formed tenant identifier.</exception>
    Task InvalidateTenantAsync(string tenantId, CancellationToken cancellationToken = default);
}
