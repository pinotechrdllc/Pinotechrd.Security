namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Provides the schema name to be used for the current database operation.
/// </summary>
public interface ISchemaProvider
{
    /// <summary>
    /// Gets the name of the schema for the current context.
    /// </summary>
    string GetSchemaName();

    /// <summary>
    /// Gets the default schema name (e.g., "public" or "identity").
    /// </summary>
    string GetDefaultSchema();
}
