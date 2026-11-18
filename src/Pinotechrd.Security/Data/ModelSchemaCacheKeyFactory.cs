using Microsoft.EntityFrameworkCore.Infrastructure;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Data;

/// <summary>
/// Custom ModelCacheKeyFactory that includes the schema name and the security model settings in the cache key.
/// Required to ensure EF Core doesn't reuse the same model across different dynamic schemas.
/// Registered by <see cref="PinotechrdSecurityDbContextOptionsExtensions.UsePinotechrdSecurity(Microsoft.EntityFrameworkCore.DbContextOptionsBuilder, Action{PinotechrdSecurityModelOptions}?)"/>.
/// </summary>
public class ModelSchemaCacheKeyFactory : IModelCacheKeyFactory
{
    /// <summary>
    /// Creates a model cache key including schema when available.
    /// </summary>
    public object Create(Microsoft.EntityFrameworkCore.DbContext context, bool designTime)
    {
        if (context is ISchemaAwareContext schemaAware)
        {
            var settings = context.GetService<IDbContextOptions>()
                .FindExtension<PinotechrdSecurityDbContextOptionsExtension>()?.Settings;
            return (context.GetType(), schemaAware.SchemaName, settings, designTime);
        }

        return (context.GetType(), designTime);
    }

    // Support for EF Core 6/7/8/9/10
    /// <summary>
    /// Creates a model cache key for runtime scenarios.
    /// </summary>
    public object Create(Microsoft.EntityFrameworkCore.DbContext context) => Create(context, false);
}

/// <summary>
/// Internal marker interface to access schema name from the DB Context.
/// </summary>
public interface ISchemaAwareContext
{
    /// <summary>
    /// Gets the dynamic schema name associated with the current context, or <see langword="null"/> when the
    /// model has no tenant schema (<see cref="TenantSchemaMode.SearchPath"/>).
    /// </summary>
    string? SchemaName { get; }
}
