namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Defines a store for resolving and validating tenants.
/// </summary>
public interface ITenantStore
{
    /// <summary>
    /// Checks if a tenant exists and is active.
    /// </summary>
    Task<bool> TenantExistsAsync(string tenantId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Domain interface for entities that are tenant-scoped.
/// </summary>
public interface ITenantEntity
{
    /// <summary>
    /// Gets or sets the tenant identifier that owns the entity.
    /// </summary>
    string TenantId { get; set; }
}
