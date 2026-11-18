using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Tenancy;

/// <summary>
/// Domain-aware implementation of ISchemaProvider that uses TenantContext.
/// </summary>
public class DbSchemaProvider : ISchemaProvider
{
    private readonly TenantContext _tenantContext;
    private const string DEFAULT_SCHEMA = "identity";

    /// <summary>
    /// Initializes the schema provider.
    /// </summary>
    public DbSchemaProvider(TenantContext tenantContext)
    {
        _tenantContext = tenantContext;
    }

    /// <inheritdoc />
    public string GetSchemaName()
    {
        // If we have a tenant context with a derived schema name, use it.
        // Otherwise, fall back to the identity schema.
        return _tenantContext.SchemaName ?? DEFAULT_SCHEMA;
    }

    /// <inheritdoc />
    public string GetDefaultSchema() => DEFAULT_SCHEMA;
}
