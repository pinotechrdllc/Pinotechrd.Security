using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using DotNet.Testcontainers.Networks;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Pinotechrd.Security.Data;
using Testcontainers.PostgreSql;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// PostgreSQL behind PgBouncer, in session and in transaction mode, with one server connection per database so two
/// clients must share it. Like the other PostgreSQL tests, these fail instead of skipping when Docker is not available.
/// </summary>
public sealed class PgBouncerFixture : IAsyncLifetime
{
    public const string BouncerImage = "edoburu/pgbouncer:v1.26.0-p0";

    private INetwork? _network;
    private PostgreSqlContainer? _postgres;
    private IContainer? _transaction;
    private IContainer? _session;

    public string Direct { get; private set; } = "";

    public async Task InitializeAsync()
    {
        try
        {
            _network = new NetworkBuilder().Build();
            await _network.CreateAsync();
            _postgres = new PostgreSqlBuilder(PostgresFixture.Image).WithNetwork(_network).WithNetworkAliases("pg").Build();
            await _postgres.StartAsync();
            Direct = new NpgsqlConnectionStringBuilder(_postgres.GetConnectionString()) { Database = "postgres" }.ConnectionString;
            await PgProvisioning.ExecuteAsync(Direct, "CREATE DATABASE pooled_search_path; CREATE DATABASE pooled_model;");
            await PgProvisioning.ProvisionAsync(Database("pooled_search_path"), TenantSchemaMode.SearchPath, "a", "b");
            await PgProvisioning.ProvisionAsync(Database("pooled_model"), TenantSchemaMode.SchemaPerTenantInModel, "a", "b");

            _transaction = Bouncer("transaction");
            _session = Bouncer("session");
            await Task.WhenAll(_transaction.StartAsync(), _session.StartAsync());
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"The pooler tests need a Docker daemon able to run '{PostgresFixture.Image}' and '{BouncerImage}'. " +
                "They fail instead of skipping so that a missing Docker cannot hide a broken tenant-isolation guarantee.", ex);
        }
    }

    private string Database(string name) => new NpgsqlConnectionStringBuilder(Direct) { Database = name }.ConnectionString;

    private IContainer Bouncer(string poolMode) => new ContainerBuilder(BouncerImage)
        .WithNetwork(_network!)
        .WithEnvironment("DB_HOST", "pg")
        .WithEnvironment("DB_PORT", "5432")
        .WithEnvironment("DB_USER", PostgreSqlBuilder.DefaultUsername)
        .WithEnvironment("DB_PASSWORD", PostgreSqlBuilder.DefaultPassword)
        .WithEnvironment("AUTH_TYPE", "plain")
        .WithEnvironment("POOL_MODE", poolMode)
        .WithEnvironment("DEFAULT_POOL_SIZE", "1")
        .WithPortBinding(5432, true)
        .WithWaitStrategy(Wait.ForUnixContainer().UntilInternalTcpPortIsAvailable(5432))
        .Build();

    /// <summary>
    /// A connection string through the pooler. By default Npgsql's own pooling is off, so each context is its own client;
    /// <paramref name="npgsqlPooling"/> keeps it on, as production does.
    /// </summary>
    public string Through(string poolMode, string database, bool npgsqlPooling = false)
    {
        var bouncer = poolMode == "transaction" ? _transaction! : _session!;
        return new NpgsqlConnectionStringBuilder
        {
            Host = bouncer.Hostname,
            Port = bouncer.GetMappedPublicPort(5432),
            Username = PostgreSqlBuilder.DefaultUsername,
            Password = PostgreSqlBuilder.DefaultPassword,
            Database = database,
            Pooling = npgsqlPooling,
        }.ConnectionString;
    }

    public async Task DisposeAsync()
    {
        NpgsqlConnection.ClearAllPools();
        if (_transaction != null) await _transaction.DisposeAsync();
        if (_session != null) await _session.DisposeAsync();
        if (_postgres != null) await _postgres.DisposeAsync();
        if (_network != null) await _network.DisposeAsync();
    }
}

public class PostgresPoolerTests(PgBouncerFixture pooler) : IClassFixture<PgBouncerFixture>
{
    private static async Task<int> CountRolesNamedAsync(DbContext db, string name) =>
        (await db.Database.SqlQueryRaw<int>("SELECT count(*)::int AS \"Value\" FROM roles WHERE \"Name\" = {0}", name).ToListAsync()).Single();

    [Fact]
    public async Task SearchPath_ShouldRefuseToBind_ThroughATransactionModePooler()
    {
        await using var db = PgProvisioning.NewContext(pooler.Through("transaction", "pooled_search_path"), TenantSchemaMode.SearchPath, "a");

        var act = () => db.Database.OpenConnectionAsync();

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*connection pooler*");
        db.Database.GetDbConnection().State.Should().Be(System.Data.ConnectionState.Closed);
    }

    [Fact]
    public async Task SearchPath_ShouldRefuseToBind_ThroughATransactionModePooler_WithNpgsqlPoolingOn()
    {
        var cs = pooler.Through("transaction", "pooled_search_path", npgsqlPooling: true);
        for (var i = 0; i < 3; i++)
        {
            await using var db = PgProvisioning.NewContext(cs, TenantSchemaMode.SearchPath, i % 2 == 0 ? "a" : "b");
            var act = () => db.Database.OpenConnectionAsync();
            await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*connection pooler*");
        }
    }

    [Fact]
    public async Task SearchPath_ShouldRefuseToBind_ThroughASessionModePooler_UnlessDeclared()
    {
        await using var db = PgProvisioning.NewContext(pooler.Through("session", "pooled_search_path"), TenantSchemaMode.SearchPath, "a");

        var act = () => db.Database.OpenConnectionAsync();

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*ConnectionPoolerUsesSessionMode*");
    }

    [Fact]
    public async Task SearchPath_ShouldKeepEachTenantOnItsSchema_ThroughADeclaredSessionModePooler()
    {
        var cs = pooler.Through("session", "pooled_search_path");
        for (var i = 0; i < 4; i++)
        {
            var tenant = i % 2 == 0 ? "a" : "b";
            await using var db = PgProvisioning.NewContext(cs, TenantSchemaMode.SearchPath, tenant, o => o.ConnectionPoolerUsesSessionMode = true);
            var name = "session-" + tenant + "-" + i;
            db.Roles.Add(new Hosting.HostRole { Id = Guid.NewGuid(), Name = name, NormalizedName = name.ToUpperInvariant() });
            await db.SaveChangesAsync();
            (await CountRolesNamedAsync(db, name)).Should().Be(1);
            (await db.Database.SqlQueryRaw<string>("SELECT current_schema() AS \"Value\"").ToListAsync()).Single().Should().Be("tenant_" + tenant);
        }
    }

    [Fact]
    public async Task SchemaPerTenantInModel_ShouldKeepTenantsApart_ThroughATransactionModePooler()
    {
        var cs = pooler.Through("transaction", "pooled_model");
        await using var a = PgProvisioning.NewContext(cs, TenantSchemaMode.SchemaPerTenantInModel, "a");
        await using var b = PgProvisioning.NewContext(cs, TenantSchemaMode.SchemaPerTenantInModel, "b");

        a.Roles.Add(new Hosting.HostRole { Id = Guid.NewGuid(), Name = "pooled-a", NormalizedName = "POOLED-A" });
        b.Roles.Add(new Hosting.HostRole { Id = Guid.NewGuid(), Name = "pooled-b", NormalizedName = "POOLED-B" });
        await a.SaveChangesAsync();
        await b.SaveChangesAsync();

        (await a.Roles.CountAsync(r => r.Name == "pooled-a")).Should().Be(1);
        (await a.Roles.CountAsync(r => r.Name == "pooled-b")).Should().Be(0);
        (await b.Roles.CountAsync(r => r.Name == "pooled-b")).Should().Be(1);
    }
}
