using System.Data;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Tests.Data;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// <c>SearchPath</c> mode needs <c>standard_conforming_strings = on</c>: the session-change scanner reads strings the way PostgreSQL
/// does with it on. A dedicated database is altered here, so no other test class is affected.
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresConformingStringsTests(PostgresFixture postgres) : IAsyncLifetime
{
    // The reviewer's input: with standard_conforming_strings off, '\'' is one string and the rest is a SET statement.
    private const string Backslash = "SELECT '\\''; SET search_path TO x; --'";

    private string _cs = null!;

    public async Task InitializeAsync()
    {
        _cs = await postgres.CreateDatabaseAsync();
        await PgProvisioning.ProvisionAsync(_cs, TenantSchemaMode.SearchPath, "a");
    }

    public Task DisposeAsync()
    {
        NpgsqlConnection.ClearAllPools();
        return Task.CompletedTask;
    }

    private WidgetDb Db(string applicationName)
    {
        var builder = new DbContextOptionsBuilder<WidgetDb>().UseNpgsql(_cs + ";Application Name=" + applicationName);
        builder.UsePinotechrdSecurity(o => o.TenantSchemaMode = TenantSchemaMode.SearchPath);
        return new WidgetDb(builder.Options, new Pinotechrd.Security.Tenancy.DbSchemaProvider(SecDbFactory.Tenant("a")));
    }

    private async Task SetConformingStringsAsync(string value)
    {
        var database = new NpgsqlConnectionStringBuilder(_cs).Database;
        await PgProvisioning.ExecuteAsync(_cs, $"ALTER DATABASE \"{database}\" SET standard_conforming_strings = {value}");
    }

    [Fact]
    public async Task Open_ShouldBind_WhenStandardConformingStringsIsOn_TheDefault()
    {
        await using var db = Db("scs-on");

        (await db.Database.SqlQueryRaw<string>("SELECT current_schema() AS \"Value\"").ToListAsync()).Should().Equal("tenant_a");
        (await PgProvisioning.ScalarAsync(_cs, "SHOW standard_conforming_strings")).Should().Be("on");
    }

    [Fact]
    public async Task BackslashInput_ShouldBeHarmlessWithTheDefaultSetting_NeverChangingThePath()
    {
        await using var db = Db("scs-default-input");
        await db.Database.OpenConnectionAsync();

        // Whatever the library or the server make of it, the session path must still be the tenant's afterwards.
        try { await db.Database.ExecuteSqlRawAsync(Backslash); }
        catch (Exception ex) when (ex is InvalidOperationException or PostgresException or NpgsqlException) { }

        var read = db.Database.GetDbConnection().CreateCommand();
        read.CommandText = "SELECT current_setting('search_path')";
        (await read.ExecuteScalarAsync()).Should().Be("tenant_a");
    }

    [Fact]
    public async Task Open_ShouldBeRefusedWithTheConnectionClosed_WhenTheDatabaseTurnsStandardConformingStringsOff()
    {
        await SetConformingStringsAsync("off");
        try
        {
            // A new application name means a new pool, so no connection opened before the ALTER is reused.
            await using var db = Db("scs-off-" + Guid.NewGuid().ToString("N")[..6]);

            var open = () => db.Database.OpenConnectionAsync();
            var query = () => db.Database.ExecuteSqlRawAsync("SELECT 1");

            await open.Should().ThrowAsync<InvalidOperationException>().WithMessage("*standard_conforming_strings*");
            await query.Should().ThrowAsync<InvalidOperationException>().WithMessage("*standard_conforming_strings*");
            db.Database.GetDbConnection().State.Should().Be(ConnectionState.Closed);
        }
        finally
        {
            await SetConformingStringsAsync("on");
        }
    }

    [Fact]
    public async Task TheBackslashInput_ShouldNeverRun_WhenStandardConformingStringsIsOff()
    {
        await SetConformingStringsAsync("off");
        try
        {
            await using var db = Db("scs-off-input-" + Guid.NewGuid().ToString("N")[..6]);

            var act = () => db.Database.ExecuteSqlRawAsync(Backslash);

            // Refused before anything is sent: the connection could not even be bound.
            await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*standard_conforming_strings*");
            db.Database.GetDbConnection().State.Should().Be(ConnectionState.Closed);
        }
        finally
        {
            await SetConformingStringsAsync("on");
        }
    }
}
