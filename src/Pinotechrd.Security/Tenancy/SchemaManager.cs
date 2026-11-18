using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Interfaces;
using System.Text.RegularExpressions;

namespace Pinotechrd.Security.Tenancy;

/// <summary>
/// Handles database schema-level operations like creation and migration execution.
/// </summary>
public class SchemaManager
{
    private readonly ISecurityDbContext _db;
    private static readonly Regex SchemaNameRegex = new("^[A-Za-z_][A-Za-z0-9_]*$", RegexOptions.Compiled);

    /// <summary>
    /// Initializes the schema manager.
    /// </summary>
    public SchemaManager(ISecurityDbContext db)
    {
        _db = db;
    }

    /// <summary>
    /// Ensures the physical schema exists in the PostgreSQL database.
    /// </summary>
    public async Task CreateSchemaAsync(string schemaName)
    {
        if (string.IsNullOrWhiteSpace(schemaName))
            throw new ArgumentException("Schema name cannot be empty.", nameof(schemaName));

        if (!SchemaNameRegex.IsMatch(schemaName))
            throw new ArgumentException("Schema name contains invalid characters.", nameof(schemaName));

        if (_db is DbContext context)
        {
            var sql = "CREATE SCHEMA IF NOT EXISTS \"" + schemaName + "\";";
            await context.Database.ExecuteSqlRawAsync(sql);
        }
        else
        {
            throw new InvalidOperationException("The provided security context is not an EF Core DbContext.");
        }
    }

    /// <summary>
    /// Applies migrations to the specified dynamic schema.
    /// Note: The SchemaProvider must be configured to return this schemaName 
    /// for the current context during this operation.
    /// </summary>
    public async Task ApplyMigrationsAsync()
    {
        if (_db is DbContext context)
        {
            await context.Database.MigrateAsync();
        }
    }
}
