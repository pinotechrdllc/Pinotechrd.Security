using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>A context type of its own, so the migration below belongs to it alone.</summary>
public sealed class MigDb : PinotechrdSecurityDbContext<HostUser, HostRole>
{
    public MigDb(DbContextOptions<MigDb> options, ISchemaProvider schemaProvider) : base(options, schemaProvider)
    {
    }

    /// <summary>The mode the migration is generated for, as <c>dotnet ef migrations add</c> would build it.</summary>
    public static TenantSchemaMode DesignMode { get; set; }

    public static MigDb Create(string connectionString, TenantSchemaMode mode, string tenant)
    {
        var builder = new DbContextOptionsBuilder<MigDb>().UseNpgsql(connectionString);
        builder.UsePinotechrdSecurity(o =>
        {
            o.TenantSchemaMode = mode;
            o.ExcludeCatalogFromMigrations = true;
        });
        return new MigDb(builder.Options, new DbSchemaProvider(SecDbFactory.Tenant(tenant)));
    }
}

/// <summary>
/// The initial migration <c>dotnet ef migrations add</c> would generate: the differences between no model and the model of
/// a context built at design time for one tenant ("design").
/// </summary>
[DbContext(typeof(MigDb))]
[Migration("20261120000000_InitialSecurity")]
public sealed class InitialSecurityMigration : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        using var design = MigDb.Create("Host=design-time-only", MigDb.DesignMode, "design");
        var model = design.GetService<IDesignTimeModel>().Model.GetRelationalModel();
        migrationBuilder.Operations.AddRange(design.GetService<IMigrationsModelDiffer>().GetDifferences(null, model));
    }
}

/// <summary>
/// EF Core migrations applied once per tenant, as the README describes for <see cref="TenantSchemaMode.SearchPath"/>, and
/// why they cannot work that way in <see cref="TenantSchemaMode.SchemaPerTenantInModel"/>.
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresMigrationsTests(PostgresFixture postgres)
{
    private static async Task<long> CountAsync(string cs, string sql) =>
        Convert.ToInt64(await PgProvisioning.ScalarAsync(cs, sql));

    private static Task<long> TablesInAsync(string cs, string schema) =>
        CountAsync(cs, $"SELECT count(*) FROM information_schema.tables WHERE table_schema = '{schema}'");

    private static Task<long> HistoryRowsAsync(string cs, string schema) =>
        CountAsync(cs, $"SELECT count(*) FROM \"{schema}\".\"__EFMigrationsHistory\"");

    [Fact]
    public async Task SearchPath_MigrateAsyncPerTenant_ShouldGiveEachTenantItsTablesAndItsOwnHistory()
    {
        var cs = await postgres.CreateDatabaseAsync();
        MigDb.DesignMode = TenantSchemaMode.SearchPath;
        foreach (var tenant in new[] { "a", "b" })
        {
            await PgProvisioning.ExecuteAsync(cs, $"CREATE SCHEMA \"{TenantIdentifier.ToSchemaName(tenant)}\"");
            await using var db = MigDb.Create(cs, TenantSchemaMode.SearchPath, tenant);
            await db.Database.MigrateAsync();
            (await db.Database.GetPendingMigrationsAsync()).Should().BeEmpty();
        }

        var (a, b) = (TenantIdentifier.ToSchemaName("a"), TenantIdentifier.ToSchemaName("b"));
        (await TablesInAsync(cs, a)).Should().BeGreaterThan(1).And.Be(await TablesInAsync(cs, b));
        (await HistoryRowsAsync(cs, a)).Should().Be(1);
        (await HistoryRowsAsync(cs, b)).Should().Be(1);
        (await CountAsync(cs, "SELECT count(*) FROM information_schema.tables WHERE table_name = '__EFMigrationsHistory'"))
            .Should().Be(2, "each tenant keeps its own history, none is shared");

        // The tables work: a user created in tenant a is not seen from tenant b.
        await using (var db = MigDb.Create(cs, TenantSchemaMode.SearchPath, "a"))
        {
            db.Users.Add(new HostUser { UserName = "u@a.test", NormalizedUserName = "U@A.TEST" });
            await db.SaveChangesAsync();
        }

        await using (var db = MigDb.Create(cs, TenantSchemaMode.SearchPath, "b"))
        {
            (await db.Users.CountAsync()).Should().Be(0);
        }
    }

    [Fact]
    public void SchemaPerTenantInModel_AGeneratedMigration_NamesTheDesignTimeTenantsSchema_SoItCannotServeOtherTenants()
    {
        // What `dotnet ef migrations add` generates in this mode: every table operation carries the schema of the tenant
        // the design-time context resolved, so applying it "per tenant" writes that one schema (README, "Migrations and
        // the schema mode").
        using var design = MigDb.Create("Host=design-time-only", TenantSchemaMode.SchemaPerTenantInModel, "design");
        var operations = design.GetService<IMigrationsModelDiffer>()
            .GetDifferences(null, design.GetService<IDesignTimeModel>().Model.GetRelationalModel());

        var schemas = operations.OfType<Microsoft.EntityFrameworkCore.Migrations.Operations.CreateTableOperation>()
            .Select(o => o.Schema).Distinct().ToList();
        schemas.Should().Equal(TenantIdentifier.ToSchemaName("design"));
    }
}
