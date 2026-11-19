using Microsoft.EntityFrameworkCore;
using Npgsql;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;

namespace Pinotechrd.Security.Tests.Postgres;

internal static class PgProvisioning
{
    public static readonly TenantSchemaMode[] Modes = [TenantSchemaMode.SchemaPerTenantInModel, TenantSchemaMode.SearchPath];

    public static IEnumerable<object[]> BothModes() => Modes.Select(m => new object[] { m });

    /// <summary>A context for <paramref name="tenant"/> on PostgreSQL, built the way the README says an application builds it.</summary>
    public static SecDb NewContext(
        string connectionString,
        TenantSchemaMode mode,
        string? tenant,
        Action<PinotechrdSecurityModelOptions>? configure = null,
        TenantResolutionOptions? tenancy = null)
    {
        var builder = new DbContextOptionsBuilder<SecDb>().UseNpgsql(connectionString);
        builder.UsePinotechrdSecurity(o =>
        {
            o.TenantSchemaMode = mode;
            configure?.Invoke(o);
        });
        return new SecDb(builder.Options, new DbSchemaProvider(SecDbFactory.Tenant(tenant), tenancy));
    }

    /// <summary>
    /// Provisions tenants as the README documents: create the schema, then run the generated create script from a context
    /// whose tenant is set. The first tenant's script also creates the catalog tables; later tenants exclude them.
    /// </summary>
    public static Task ProvisionAsync(string connectionString, TenantSchemaMode mode, params string[] tenants) =>
        ProvisionAsync(connectionString, mode, null, tenants);

    /// <summary>Same as above, with extra model options (for example <c>MapRefreshTokens</c>) applied to every tenant's script.</summary>
    public static async Task ProvisionAsync(
        string connectionString,
        TenantSchemaMode mode,
        Action<PinotechrdSecurityModelOptions>? configure,
        params string[] tenants)
    {
        for (var i = 0; i < tenants.Length; i++)
        {
            var first = i == 0;
            await using var db = NewContext(connectionString, mode, tenants[i], o =>
            {
                o.ExcludeCatalogFromMigrations = !first;
                configure?.Invoke(o);
            });
            var schema = TenantIdentifier.ToSchemaName(tenants[i]);
            var createSchema = $"CREATE SCHEMA IF NOT EXISTS \"{schema}\"";
            await db.Database.ExecuteSqlRawAsync(createSchema);
            await db.Database.ExecuteSqlRawAsync(db.Database.GenerateCreateScript());
        }
    }

    /// <summary>Runs SQL on a plain Npgsql connection, outside the library (an administrator's session).</summary>
    public static async Task<object?> ScalarAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return await command.ExecuteScalarAsync();
    }

    public static async Task ExecuteAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }
}
