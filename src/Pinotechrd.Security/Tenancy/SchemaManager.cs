using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Interfaces;
using System.Text.RegularExpressions;

namespace Pinotechrd.Security.Tenancy;

/// <summary>
/// Handles database schema-level operations like creation and migration execution.
/// </summary>
public class SchemaManager
{
    private const string SchemaNameRule =
        "Schema name must match ^[a-z_][a-z0-9_]{0,62}$: lower-case letters, digits and '_', not starting with a digit, at most 63 characters.";

    private readonly ISecurityDbContext _db;

    // Lower case only, because the search_path check compares lower-case names; at most 63 characters, because
    // PostgreSQL silently truncates longer identifiers. \z rather than $, so a trailing newline is rejected.
    private static readonly Regex SchemaNameRegex = new(@"^[a-z_][a-z0-9_]{0,62}\z", RegexOptions.Compiled);

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
    /// <param name="schemaName">Schema name; must match <c>^[a-z_][a-z0-9_]{0,62}$</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="ArgumentException"><paramref name="schemaName"/> does not match the rule.</exception>
    public async Task CreateSchemaAsync(string schemaName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(schemaName))
            throw new ArgumentException("Schema name cannot be empty.", nameof(schemaName));

        if (!SchemaNameRegex.IsMatch(schemaName))
            throw new ArgumentException(SchemaNameRule, nameof(schemaName));

        if (_db is DbContext context)
        {
            var sql = "CREATE SCHEMA IF NOT EXISTS \"" + schemaName + "\";";
            await context.Database.ExecuteSqlRawAsync(sql, cancellationToken);
        }
        else
        {
            throw new InvalidOperationException("The provided security context is not an EF Core DbContext.");
        }
    }

    /// <summary>
    /// Ensures the schema of a tenant exists, named by <see cref="TenantIdentifier.ToSchemaName"/>.
    /// </summary>
    /// <param name="tenantId">Tenant identifier; must be a well-formed tenant identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="ArgumentException"><paramref name="tenantId"/> is not a well-formed tenant identifier.</exception>
    public Task CreateTenantSchemaAsync(string tenantId, CancellationToken cancellationToken = default)
    {
        return CreateSchemaAsync(TenantIdentifier.ToSchemaName(tenantId), cancellationToken);
    }

    /// <summary>
    /// Applies migrations to the specified dynamic schema.
    /// Note: The SchemaProvider must be configured to return this schemaName 
    /// for the current context during this operation.
    /// </summary>
    public async Task ApplyMigrationsAsync(CancellationToken cancellationToken = default)
    {
        if (_db is DbContext context)
        {
            await context.Database.MigrateAsync(cancellationToken);
        }
    }
}
