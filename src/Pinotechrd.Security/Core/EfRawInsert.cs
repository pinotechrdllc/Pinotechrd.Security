using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Single-row <c>INSERT</c> for the EF Core stores, which never use the change tracker.
/// </summary>
internal static class EfRawInsert
{
    /// <summary>
    /// Inserts one row with a parameterised <c>INSERT</c> built from the model's table and column names, without
    /// the change tracker, so the application's pending changes are not saved with it.
    /// </summary>
    public static Task<int> InsertAsync(
        DbContext context,
        IEntityType entityType,
        (string Property, object? Value)[] values,
        CancellationToken cancellationToken)
    {
        var table = StoreObjectIdentifier.Table(entityType.GetTableName()!, entityType.GetSchema());
        var sql = context.GetService<ISqlGenerationHelper>();

        var properties = values.Select(v => entityType.FindProperty(v.Property)!).ToArray();
        var columns = properties.Select(p => sql.DelimitIdentifier(p.GetColumnName(table)!));
        var placeholders = values.Select((_, i) => "{" + i + "}");
        var command = $"INSERT INTO {sql.DelimitIdentifier(table.Name, table.Schema)} ({string.Join(", ", columns)}) " +
                      $"VALUES ({string.Join(", ", placeholders)})";

        // Typed parameters from each column's type mapping: a bare null (DBNull) has no store type, and the
        // mapping also applies any value converter the model configures.
        using var factory = context.Database.GetDbConnection().CreateCommand();
        var parameters = properties
            .Select((property, i) => (object)property.GetRelationalTypeMapping()
                .CreateParameter(factory, "p" + i, values[i].Value, property.IsNullable))
            .ToArray();

        return context.Database.ExecuteSqlRawAsync(command, parameters, cancellationToken);
    }
}
