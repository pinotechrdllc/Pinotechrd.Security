namespace Pinotechrd.Security.Tenancy;

/// <summary>
/// Scoped context holder for the current resolved tenant ID.
/// </summary>
public class TenantContext
{
    /// <summary>
    /// Gets the current Tenant ID if resolved.
    /// </summary>
    public string? TenantId { get; private set; }

    /// <summary>
    /// Gets the schema name of the current tenant (see <see cref="TenantIdentifier.ToSchemaName"/>), or
    /// <see langword="null"/> when no tenant is resolved.
    /// </summary>
    public string? SchemaName => TenantId != null
        ? TenantIdentifier.ToSchemaName(TenantId)
        : null;

    /// <summary>
    /// Sets the current Tenant ID.
    /// </summary>
    /// <exception cref="ArgumentException">The identifier is not valid according to <see cref="TenantIdentifier.IsValid"/>.</exception>
    public void SetTenant(string tenantId)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
            throw new ArgumentException("Tenant ID cannot be empty.", nameof(tenantId));

        if (!TenantIdentifier.IsValid(tenantId))
            throw new ArgumentException("Tenant ID is not a valid tenant identifier.", nameof(tenantId));

        TenantId = tenantId;
    }
}
