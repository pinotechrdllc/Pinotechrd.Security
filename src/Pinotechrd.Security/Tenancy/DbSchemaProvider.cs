using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Tenancy;

/// <summary>
/// Domain-aware implementation of ISchemaProvider that uses TenantContext.
/// </summary>
/// <remarks>
/// With no tenant resolved, <see cref="GetSchemaName"/> throws, unless
/// <see cref="TenantResolutionOptions.UseSharedSchemaWhenNoTenant"/> is set, in which case it returns the
/// shared <c>identity</c> schema. Silently falling back to a shared schema would read or write another
/// tenant's data in the wrong place.
/// </remarks>
public class DbSchemaProvider : ISchemaProvider
{
    private readonly TenantContext _tenantContext;
    private readonly bool _useSharedSchemaWhenNoTenant;
    private const string DEFAULT_SCHEMA = "identity";

    /// <summary>
    /// Initializes the schema provider. With no tenant resolved, <see cref="GetSchemaName"/> throws.
    /// </summary>
    public DbSchemaProvider(TenantContext tenantContext) : this(tenantContext, null)
    {
    }

    /// <summary>
    /// Initializes the schema provider with the tenancy options.
    /// </summary>
    public DbSchemaProvider(TenantContext tenantContext, TenantResolutionOptions? options)
    {
        _tenantContext = tenantContext;
        _useSharedSchemaWhenNoTenant = options?.UseSharedSchemaWhenNoTenant == true;
    }

    /// <inheritdoc />
    /// <exception cref="InvalidOperationException">No tenant is resolved and the shared schema is not allowed.</exception>
    public string GetSchemaName()
    {
        var schema = _tenantContext.SchemaName;
        if (schema != null) return schema;

        if (_useSharedSchemaWhenNoTenant) return DEFAULT_SCHEMA;

        throw new InvalidOperationException(
            "No tenant is resolved for this operation. Resolve the tenant first (UseTenantResolution or TenantContext.SetTenant), " +
            "or set TenantResolutionOptions.UseSharedSchemaWhenNoTenant to use the shared schema.");
    }

    /// <inheritdoc />
    public string GetDefaultSchema() => DEFAULT_SCHEMA;
}
