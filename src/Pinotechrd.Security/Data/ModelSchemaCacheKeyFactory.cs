using Microsoft.EntityFrameworkCore.Infrastructure;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Data;

/// <summary>
/// Custom ModelCacheKeyFactory that includes the schema name in the cache key.
/// Required to ensure EF Core doesn't reuse the same model across different dynamic schemas.
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
            return (context.GetType(), schemaAware.SchemaName, designTime);
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
    /// Gets the dynamic schema name associated with the current context.
    /// </summary>
    string SchemaName { get; }
}
