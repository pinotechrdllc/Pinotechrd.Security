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
    /// Gets a sanitized schema name derived from the Tenant ID (e.g., "tenant_uuid").
    /// </summary>
    public string? SchemaName => TenantId != null 
        ? $"tenant_{TenantId.ToLower().Replace("-", "_")}" 
        : null;

    /// <summary>
    /// Sets the current Tenant ID.
    /// </summary>
    public void SetTenant(string tenantId)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
            throw new ArgumentException("Tenant ID cannot be empty.", nameof(tenantId));

        TenantId = tenantId;
    }
}
