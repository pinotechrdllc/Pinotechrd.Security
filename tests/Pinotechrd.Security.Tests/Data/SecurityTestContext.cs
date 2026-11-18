using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Hosting;

namespace Pinotechrd.Security.Tests.Data;

/// <summary>A concrete context over the library's base context, as an application would write it.</summary>
public sealed class SecDb : PinotechrdSecurityDbContext<HostUser, HostRole>
{
    public SecDb(DbContextOptions<SecDb> options, ISchemaProvider schemaProvider) : base(options, schemaProvider)
    {
    }
}

internal static class SecDbFactory
{
    public static TenantContext Tenant(string? id)
    {
        var tenant = new TenantContext();
        if (id != null) tenant.SetTenant(id);
        return tenant;
    }

    /// <summary>Builds a context on SQLite. <paramref name="usePinotechrd"/> false leaves out UsePinotechrdSecurity().</summary>
    public static SecDb Create(
        SqliteConnection connection,
        string? tenantId,
        bool usePinotechrd = true,
        Action<PinotechrdSecurityModelOptions>? configure = null,
        TenantResolutionOptions? tenancy = null)
    {
        var builder = new DbContextOptionsBuilder<SecDb>().UseSqlite(connection);
        if (usePinotechrd) builder.UsePinotechrdSecurity(configure);
        return new SecDb(builder.Options, new DbSchemaProvider(Tenant(tenantId), tenancy));
    }

    public static SqliteConnection OpenMemory()
    {
        var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        return connection;
    }
}
