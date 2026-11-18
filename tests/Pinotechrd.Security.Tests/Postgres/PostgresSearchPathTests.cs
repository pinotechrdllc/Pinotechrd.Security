using System.Collections.Concurrent;
using System.Data;
using System.Reflection;
using System.Transactions;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;
using Xunit.Sdk;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// <c>TenantSchemaMode.SearchPath</c> on real PostgreSQL connections, through Npgsql's pool: binding, the refusals, SQL that
/// changes the session, ordinary EF SQL with colliding column names, and tenants alternating on shared physical connections.
/// Raw reads of the session settings go through the context's own connection with a plain ADO.NET command (the library does not check those).
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresSearchPathTests(PostgresFixture postgres) : IAsyncLifetime
{
    private string _cs = null!;

    public async Task InitializeAsync()
    {
        _cs = await postgres.CreateDatabaseAsync();
        await PgProvisioning.ProvisionAsync(_cs, TenantSchemaMode.SearchPath, "a", "b");
        foreach (var tenant in new[] { "a", "b" })
        {
            await PgProvisioning.ExecuteAsync(_cs, $"""
                CREATE TABLE tenant_{tenant}."Widgets" ("Id" integer PRIMARY KEY, "Role" text NOT NULL DEFAULT '', "Schema" text NOT NULL DEFAULT '',
                    "SearchPath" text NOT NULL DEFAULT '', "Reset" text NOT NULL DEFAULT '', "Discard" text NOT NULL DEFAULT '');
                CREATE TABLE tenant_{tenant}.snake_widgets (id integer PRIMARY KEY, role text NOT NULL DEFAULT '', "schema" text NOT NULL DEFAULT '',
                    search_path text NOT NULL DEFAULT '', reset text NOT NULL DEFAULT '', discard text NOT NULL DEFAULT '');
                INSERT INTO tenant_{tenant}.snake_widgets (id, role) VALUES (1, '{tenant}');
                """);
        }
    }

    public Task DisposeAsync()
    {
        NpgsqlConnection.ClearAllPools();
        return Task.CompletedTask;
    }

    private WidgetDb Db(string? tenant, string? connectionOptions = null, TenantResolutionOptions? tenancy = null, string? cs = null)
    {
        var builder = new DbContextOptionsBuilder<WidgetDb>().UseNpgsql((cs ?? _cs) + (connectionOptions == null ? "" : ";" + connectionOptions));
        builder.UsePinotechrdSecurity(o => o.TenantSchemaMode = TenantSchemaMode.SearchPath);
        return new WidgetDb(builder.Options, new DbSchemaProvider(SecDbFactory.Tenant(tenant), tenancy));
    }

    private static async Task<string> SchemaAsync(DbContext db) =>
        (await db.Database.SqlQueryRaw<string>("SELECT current_schema() AS \"Value\"").ToListAsync()).Single();

    private static async Task<int> PidAsync(DbContext db) =>
        (await db.Database.SqlQueryRaw<int>("SELECT pg_backend_pid() AS \"Value\"").ToListAsync()).Single();

    /// <summary>Reads search_path, current_user and standard_conforming_strings through the context's own open connection, bypassing the library.</summary>
    private static async Task<string> SessionAsync(DbContext db)
    {
        var connection = db.Database.GetDbConnection();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT current_setting('search_path') || '|' || current_user || '|' || current_setting('standard_conforming_strings') || '|' || pg_backend_pid()";
        return (string)(await command.ExecuteScalarAsync())!;
    }

    [Fact]
    public async Task Container_ShouldRunThePinnedPostgresVersion_WithTheRaisedConnectionLimit()
    {
        (await PgProvisioning.ScalarAsync(_cs, "SHOW server_version")).As<string>().Should().StartWith("17.7");
        (await postgres.MaxConnectionsAsync()).Should().Be("400");
    }

    // ---- Binding -----------------------------------------------------------------------------

    [Fact]
    public async Task Open_ShouldBindEachConnectionToTheTenantSchemaOnly()
    {
        await using var db = Db("a");
        await db.Database.OpenConnectionAsync();

        (await SessionAsync(db)).Should().StartWith("tenant_a|");
        (await SchemaAsync(db)).Should().Be("tenant_a");
    }

    [Fact]
    public async Task Open_ShouldBeRefused_WhenNoTenantIsResolved_AndLeaveTheConnectionClosed()
    {
        await using var db = Db(null);

        var open = () => db.Database.OpenConnectionAsync();
        var query = () => db.Tenants.ToListAsync();

        await open.Should().ThrowAsync<InvalidOperationException>();
        await query.Should().ThrowAsync<InvalidOperationException>();
        db.Database.GetDbConnection().State.Should().Be(ConnectionState.Closed);
    }

    [Fact]
    public async Task Open_ShouldBeRefusedInsideATransactionScope_AndTheNextQueryRunsOnTheTenant()
    {
        using (var scope = new TransactionScope(TransactionScopeAsyncFlowOption.Enabled))
        {
            await using var inScope = Db("a");

            var open = () => inScope.Database.OpenConnectionAsync();

            await open.Should().ThrowAsync<InvalidOperationException>().WithMessage("*TransactionScope*");
            inScope.Database.GetDbConnection().State.Should().Be(ConnectionState.Closed);
        }

        await using var next = Db("a");
        (await SchemaAsync(next)).Should().Be("tenant_a");
    }

    [Fact]
    public void SharedSchemaFallback_ShouldBeRefusedAtConstruction_InSearchPathMode()
    {
        var act = () => Db(null, tenancy: new TenantResolutionOptions { UseSharedSchemaWhenNoTenant = true });

        act.Should().Throw<InvalidOperationException>().WithMessage("*UseSharedSchemaWhenNoTenant*");
    }

    // ---- Connection strings that break the binding -------------------------------------------

    [Theory]
    [InlineData("Multiplexing=true")]
    [InlineData("No Reset On Close=true")]
    [InlineData("NoResetOnClose=true")]
    [InlineData("Search Path=tenant_b")]
    [InlineData("Options=-c search_path=tenant_b")]
    [InlineData("Options=-c search\\_path=tenant_b")]
    [InlineData("Options=-c search-path=tenant_b")]
    public async Task Open_ShouldBeRefusedWithTheConnectionClosed_WhenTheConnectionStringIsUnsafe(string option)
    {
        // A separate pool per string, so a refused connection cannot be a pooled one that another test opened.
        await using var db = Db("a", option + ";Application Name=unsafe-" + Guid.NewGuid().ToString("N")[..6]);

        var open = () => db.Database.OpenConnectionAsync();

        await open.Should().ThrowAsync<InvalidOperationException>().WithMessage("*TenantSchemaMode.SearchPath*");
        db.Database.GetDbConnection().State.Should().Be(ConnectionState.Closed);
    }

    [Fact]
    public async Task Open_ShouldWork_WhenTheOptionsAreExplicitlyOff()
    {
        await using var db = Db("a", "Multiplexing=false;No Reset On Close=false");

        (await SchemaAsync(db)).Should().Be("tenant_a");
    }

    // ---- SQL that changes the session --------------------------------------------------------

    private static readonly string[] SessionChangeMethods =
    [
        nameof(SessionChangeDetectorTests.Find_ShouldRecogniseTheDocumentedSessionChanges),
        nameof(SessionChangeDetectorTests.Find_ShouldRecogniseTheSpellingsItHandles),
        nameof(SessionChangeDetectorTests.Find_ShouldStillSeeALiteralPathChangeInsideADoBlock),
        nameof(SessionChangeDetectorTests.Find_ShouldRefuseAWriteToPgSettings),
        nameof(SessionChangeDetectorTests.Find_ShouldScanTheLiteralOfAnExecute_AndRefuseAChange),
        nameof(SessionChangeDetectorTests.Find_ShouldRefuseAnExecuteBuiltAtRunTime_BecauseItCannotBeChecked)
    ];

    /// <summary>Every input of the detector's positive and bypass theories, read from their InlineData so there is one list.</summary>
    public static IEnumerable<object[]> SessionChangingInputs()
    {
        var methods = typeof(SessionChangeDetectorTests).GetMethods()
            .Where(m => SessionChangeMethods.Contains(m.Name) || m.Name.StartsWith("Bypass", StringComparison.Ordinal));
        foreach (var method in methods)
        {
            foreach (var data in method.GetCustomAttributes<InlineDataAttribute>().SelectMany(a => a.GetData(method)))
            {
                yield return [data[0]];
            }
        }
    }

    [Theory]
    [MemberData(nameof(SessionChangingInputs))]
    public async Task SessionChangingSql_ShouldBeRefusedBeforeSending_AndTheSessionStaysTheSame(string sql)
    {
        await using var db = Db("a");
        await db.Database.OpenConnectionAsync();
        var before = await SessionAsync(db);

        var act = () => db.Database.ExecuteSqlRawAsync(sql);

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*not sent*");
        (await SessionAsync(db)).Should().Be(before, "search_path, current_user and standard_conforming_strings are unchanged");
        (await SchemaAsync(db)).Should().Be("tenant_a", "the next EF command still runs on the bound tenant");
    }

    [Theory]
    [InlineData("SET search_path TO tenant_b")]
    [InlineData("SET SCHEMA 'tenant_b'")]
    [InlineData("SET \"search_path\" = tenant_b")]
    [InlineData("SET U&\"search\\005fpath\" TO tenant_b")]
    [InlineData("SET /* /* */ */ search_path TO tenant_b")]
    [InlineData("SELECT set_config('search_' || 'path', 'tenant_b', false)")]
    [InlineData("SELECT pg_catalog.\"set_config\"('search_path', 'tenant_b', false)")]
    [InlineData("DO $$ BEGIN PERFORM set_config('search_' || 'path', 'tenant_b', false); END $$")]
    [InlineData("UPDATE pg_settings SET setting = 'tenant_b' WHERE name = 'search_path'")]
    [InlineData("UPDATE pg_catalog.pg_settings SET setting = 'tenant_b' WHERE name = 'search_path'")]
    [InlineData("UPDATE \"pg_settings\" SET setting = 'tenant_b' WHERE name = 'search_path'")]
    [InlineData("DO $$ BEGIN EXECUTE ('SET search_path TO tenant_b'); END $$")]
    [InlineData("DO $$ BEGIN EXECUTE format('SET %I TO %L', 'search_path', 'tenant_b'); END $$")]
    [InlineData("DO $$ BEGIN EXECUTE 'SET search_' || 'path TO tenant_b'; END $$")]
    public async Task ControlSql_ShouldReallyChangeThePathWhenSentOutsideTheLibrary(string sql)
    {
        // Control for the test above: these spellings are real session changes on PostgreSQL, so refusing them matters.
        await using var connection = new NpgsqlConnection(_cs + ";Pooling=false");
        await connection.OpenAsync();
        await using (var set = connection.CreateCommand())
        {
            set.CommandText = "SET search_path TO tenant_a";
            await set.ExecuteNonQueryAsync();
        }

        await using (var change = connection.CreateCommand())
        {
            change.CommandText = sql;
            await change.ExecuteNonQueryAsync();
        }

        await using var read = connection.CreateCommand();
        read.CommandText = "SELECT current_setting('search_path')";
        (await read.ExecuteScalarAsync()).Should().Be("tenant_b");
    }

    [Fact]
    public async Task ControlSql_ShouldReallyChangeThePath_WhenALoneCarriageReturnEndsTheLineComment()
    {
        await using var connection = new NpgsqlConnection(_cs + ";Pooling=false");
        await connection.OpenAsync();
        await using (var change = connection.CreateCommand())
        {
            change.CommandText = "-- c\rSET search_path TO tenant_b";
            await change.ExecuteNonQueryAsync();
        }

        await using var read = connection.CreateCommand();
        read.CommandText = "SELECT current_setting('search_path')";
        (await read.ExecuteScalarAsync()).Should().Be("tenant_b");
    }

    // ---- Ordinary EF SQL with colliding names ------------------------------------------------

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PascalCaseColumns_ShouldInsertUpdateQueryAndDelete(bool inTransaction)
    {
        await using var db = Db("a");
        if (inTransaction) await db.Database.BeginTransactionAsync();

        db.Widgets.AddRange(
            new Widget { Id = 101, Role = "admin", Schema = "s", SearchPath = "p", Reset = "r", Discard = "d" },
            new Widget { Id = 102, Role = "user", Schema = "s2", SearchPath = "p2", Reset = "r2", Discard = "d2" });
        await db.SaveChangesAsync();
        var widget = await db.Widgets.SingleAsync(w => w.Id == 101);
        widget.Role = "root";
        widget.SearchPath = "p9";
        widget.Reset = "r9";
        widget.Discard = "d9";
        widget.Schema = "s9";
        await db.SaveChangesAsync();

        (await db.Widgets.Where(w => w.SearchPath == "p9" && w.Role == "root" && w.Schema == "s9").Select(w => w.Reset).ToListAsync()).Should().Equal("r9");
        await db.Widgets.Where(w => w.Id == 102).ExecuteUpdateAsync(s => s.SetProperty(w => w.SearchPath, "q").SetProperty(w => w.Role, "x"));
        (await db.Widgets.CountAsync(w => w.SearchPath == "q")).Should().Be(1);
        await db.Widgets.Where(w => w.SearchPath == "q").ExecuteDeleteAsync();
        db.Widgets.Remove(widget);
        await db.SaveChangesAsync();

        (await db.Widgets.CountAsync()).Should().Be(0);
        (await SchemaAsync(db)).Should().Be("tenant_a");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SnakeCaseColumns_ShouldInsertUpdateQueryDeleteAndUpsert(bool inTransaction)
    {
        await using var db = Db("a");
        if (inTransaction) await db.Database.BeginTransactionAsync();

        db.SnakeWidgets.AddRange(
            new SnakeWidget { Id = 201, Role = "admin", Schema = "s", SearchPath = "p", Reset = "r", Discard = "d" },
            new SnakeWidget { Id = 202, Role = "user", SearchPath = "p2" },
            new SnakeWidget { Id = 203, Role = "user", SearchPath = "p3" });
        await db.SaveChangesAsync();

        // Several rows updated in one SaveChanges (a batch of UPDATE statements) and a filter on the colliding column.
        foreach (var widget in await db.SnakeWidgets.Where(w => w.Id >= 201).ToListAsync())
        {
            widget.SearchPath = "b";
            widget.Role = "r-" + widget.Id;
            widget.Reset = "x";
            widget.Discard = "y";
        }

        await db.SaveChangesAsync();
        (await db.SnakeWidgets.CountAsync(w => w.SearchPath == "b")).Should().Be(3);

        await db.SnakeWidgets.Where(w => w.Id == 201).ExecuteUpdateAsync(s => s.SetProperty(w => w.SearchPath, "z").SetProperty(w => w.Role, "q"));
        await db.Database.ExecuteSqlRawAsync(
            "INSERT INTO snake_widgets (id, role, search_path) VALUES (201, 'new', 'upserted') " +
            "ON CONFLICT (id) DO UPDATE SET search_path = EXCLUDED.search_path, role = EXCLUDED.role, reset = 'u', discard = 'v'");
        (await db.SnakeWidgets.Where(w => w.Id == 201).Select(w => w.SearchPath).SingleAsync()).Should().Be("upserted");

        await db.SnakeWidgets.Where(w => w.SearchPath == "b").ExecuteDeleteAsync();
        db.SnakeWidgets.RemoveRange(await db.SnakeWidgets.Where(w => w.Id == 201).ToListAsync());
        await db.SaveChangesAsync();

        (await db.SnakeWidgets.Select(w => w.Id).ToListAsync()).Should().Equal(1);
        (await SchemaAsync(db)).Should().Be("tenant_a");
    }

    [Fact]
    public async Task PascalCaseUpsert_ShouldRun()
    {
        await using var db = Db("a");

        await db.Database.ExecuteSqlRawAsync(
            "INSERT INTO \"Widgets\" (\"Id\", \"Role\") VALUES (301, 'a') ON CONFLICT (\"Id\") DO UPDATE SET \"SearchPath\" = 'z', \"Role\" = EXCLUDED.\"Role\", \"Reset\" = 'r'");
        await db.Database.ExecuteSqlRawAsync(
            "INSERT INTO \"Widgets\" (\"Id\", \"Role\") VALUES (301, 'b') ON CONFLICT (\"Id\") DO UPDATE SET \"SearchPath\" = 'z', \"Role\" = EXCLUDED.\"Role\", \"Reset\" = 'r'");

        (await db.Widgets.Where(w => w.Id == 301).Select(w => w.Role + w.SearchPath).SingleAsync()).Should().Be("bz");
        await db.Widgets.Where(w => w.Id == 301).ExecuteDeleteAsync();
    }

    // ---- Pooled connections shared by alternating tenants ------------------------------------

    [Fact]
    public async Task PoolOfOne_ShouldBindEachTenantToItsOwnSchema_OnTheSamePhysicalConnection()
    {
        var pids = new List<int>();
        const string pool = "Maximum Pool Size=1;Minimum Pool Size=0;Application Name=pool-of-one";

        for (var i = 0; i < 20; i++)
        {
            var tenant = i % 2 == 0 ? "a" : "b";
            await using var db = Db(tenant, pool);

            pids.Add(await PidAsync(db));
            (await SchemaAsync(db)).Should().Be("tenant_" + tenant, $"iteration {i}");
            (await db.SnakeWidgets.Select(w => w.Role).SingleAsync()).Should().Be(tenant, $"iteration {i}");
        }

        pids.Distinct().Should().ContainSingle("a pool of one hands the same backend process to every context");
    }

    [Fact]
    public async Task TwentySequentialAlternations_ShouldNeverSeeAnotherTenantsRows()
    {
        var wrong = new List<string>();
        for (var i = 0; i < 20; i++)
        {
            var tenant = i % 2 == 0 ? "a" : "b";
            await using var db = Db(tenant, "Maximum Pool Size=3;Application Name=sequential");
            var rows = await db.SnakeWidgets.Select(w => w.Role).ToListAsync();
            if (rows.Count != 1 || rows[0] != tenant) wrong.Add($"{tenant}:{string.Join(",", rows)}");
        }

        wrong.Should().BeEmpty();
    }

    [Fact]
    public async Task FortyParallelAlternations_ShouldNeverSeeAnotherTenantsRows_OnASmallPool()
    {
        var wrong = new ConcurrentBag<string>();
        var pids = new ConcurrentBag<int>();

        await Task.WhenAll(Enumerable.Range(0, 40).Select(i => Task.Run(async () =>
        {
            var tenant = i % 2 == 0 ? "a" : "b";
            await using var db = Db(tenant, "Maximum Pool Size=3;Application Name=parallel");
            for (var q = 0; q < 3; q++)
            {
                var rows = await db.SnakeWidgets.Select(w => w.Role).ToListAsync();
                if (rows.Count != 1 || rows[0] != tenant) wrong.Add($"{tenant}:{string.Join(",", rows)}");
                if ((await SchemaAsync(db)) != "tenant_" + tenant) wrong.Add($"{tenant}: wrong schema");
            }

            pids.Add(await PidAsync(db));
        })));

        wrong.Should().BeEmpty("zero wrong-tenant rows");
        pids.Distinct().Count().Should().BeLessThanOrEqualTo(3, "the pool really was shared by the forty contexts");
    }

    // ---- Closing and reopening by hand -------------------------------------------------------

    [Fact]
    public async Task ClosingAndReopeningTheConnectionByHand_ShouldBeRefused_AndAFreshContextWorks()
    {
        await using (var db = Db("a", "Maximum Pool Size=1;Application Name=by-hand"))
        {
            await db.Database.OpenConnectionAsync();
            (await SchemaAsync(db)).Should().Be("tenant_a");
            var connection = db.Database.GetDbConnection();

            await connection.CloseAsync();
            await connection.OpenAsync();

            var query = () => SchemaAsync(db);
            await query.Should().ThrowAsync<InvalidOperationException>().WithMessage("*not bound*");
            await connection.CloseAsync();
        }

        await using var fresh = Db("a", "Maximum Pool Size=1;Application Name=by-hand");
        (await SchemaAsync(fresh)).Should().Be("tenant_a");
    }

    [Fact]
    public async Task AConnectionOpenedByTheApplication_ShouldBeRefused_UntilEfOpensItItself()
    {
        await using var db = Db("a", "Application Name=opened-by-app");
        await db.Database.GetDbConnection().OpenAsync();

        var query = () => SchemaAsync(db);

        await query.Should().ThrowAsync<InvalidOperationException>().WithMessage("*not bound*");
        await db.Database.GetDbConnection().CloseAsync();
        (await SchemaAsync(db)).Should().Be("tenant_a");
    }

    [Fact]
    public async Task ChangingTheTenantAfterTheConnectionWasBound_ShouldBeRefused()
    {
        var tenant = SecDbFactory.Tenant("a");
        var builder = new DbContextOptionsBuilder<WidgetDb>().UseNpgsql(_cs);
        builder.UsePinotechrdSecurity(o => o.TenantSchemaMode = TenantSchemaMode.SearchPath);
        await using var db = new WidgetDb(builder.Options, new DbSchemaProvider(tenant));
        await db.Database.OpenConnectionAsync();
        (await SchemaAsync(db)).Should().Be("tenant_a");

        tenant.SetTenant("b");
        var query = () => SchemaAsync(db);

        await query.Should().ThrowAsync<InvalidOperationException>().WithMessage("*another tenant*");
    }

    // ---- Documented consequence: dynamic EXECUTE in a function body --------------------------

    private const string DynamicFunction =
        "CREATE FUNCTION public.pinotechrd_make_table(t text) RETURNS void LANGUAGE plpgsql AS $$ BEGIN EXECUTE format('CREATE TABLE IF NOT EXISTS %I (id int)', t); END $$";

    [Fact]
    public async Task DocumentedLimit_AMigrationFunctionWithDynamicExecuteIsRefusedInSearchPathMode_AndNeedsAnotherMode()
    {
        // The README states it: an EXECUTE built at run time cannot be checked, so such a CREATE FUNCTION must run outside SearchPath mode.
        File.ReadAllText(SessionChangeDetectorTests.RepoFile("README.md")).Should()
            .Contain("a migration that creates such a function must run outside `SearchPath` mode");
        await using var db = Db("a");

        var act = () => db.Database.ExecuteSqlRawAsync(DynamicFunction);

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*not sent*");
        (await PgProvisioning.ScalarAsync(_cs, "SELECT count(*) FROM pg_proc WHERE proname = 'pinotechrd_make_table'")).Should().Be(0L);

        // The same statement is valid PostgreSQL: it runs on a plain connection, outside the library.
        await PgProvisioning.ExecuteAsync(_cs, DynamicFunction);
        (await PgProvisioning.ScalarAsync(_cs, "SELECT count(*) FROM pg_proc WHERE proname = 'pinotechrd_make_table'")).Should().Be(1L);
        await PgProvisioning.ExecuteAsync(_cs, "DROP FUNCTION public.pinotechrd_make_table(text)");
    }

    // ---- Pinned known limit: a function that is already in the database --------------------

    [Fact]
    public async Task PinnedKnownLimit_AnExistingFunctionThatChangesThePathIsNotSeen_AndLaterCommandsRunOnTheOtherSchema()
    {
        // The README states this limit ("A change the scanner misses persists"). This test pins it: it is meant to fail the day a
        // mitigation lands (for example re-reading the path before each command), and should then be rewritten as a refusal test.
        var readme = File.ReadAllText(SessionChangeDetectorTests.RepoFile("README.md"));
        readme.Should().Contain("server-side functions or procedures already in the database");
        readme.Should().Contain("**A change the scanner misses persists.**");
        await PgProvisioning.ExecuteAsync(_cs,
            "CREATE OR REPLACE FUNCTION public.pinotechrd_pin_path() RETURNS void LANGUAGE plpgsql AS $$ BEGIN PERFORM set_config('search_path', 'tenant_b', false); END $$");
        await using var db = Db("a", "Application Name=pinned-limit");
        await db.Database.OpenConnectionAsync();
        (await SchemaAsync(db)).Should().Be("tenant_a");

        await db.Database.ExecuteSqlRawAsync("SELECT public.pinotechrd_pin_path()");

        (await SchemaAsync(db)).Should().Be("tenant_b", "the scanner cannot see inside the existing function, so the next EF command reads the other schema");
        (await db.SnakeWidgets.Select(w => w.Role).SingleAsync()).Should().Be("b", "and it reads the other tenant's rows");
        await db.Database.CloseConnectionAsync();

        // Closing the connection ends the damage: the next open binds the tenant again.
        await using var next = Db("a", "Application Name=pinned-limit");
        (await SchemaAsync(next)).Should().Be("tenant_a");
    }

    // ---- Writes to pg_settings through EF ----------------------------------------------------

    [Fact]
    public async Task WritesToPgSettings_ShouldLeaveTheSessionUnchanged_AndSelectFromItStillWorks()
    {
        await using var db = Db("a");
        await db.Database.OpenConnectionAsync();
        var before = await SessionAsync(db);

        var update = () => db.Database.ExecuteSqlRawAsync("UPDATE pg_settings SET setting = 'tenant_b' WHERE name = 'search_path'");
        var qualified = () => db.Database.ExecuteSqlRawAsync("UPDATE pg_catalog.pg_settings SET setting = 'tenant_b' WHERE name = 'search_path'");

        await update.Should().ThrowAsync<InvalidOperationException>().WithMessage("*not sent*");
        await qualified.Should().ThrowAsync<InvalidOperationException>().WithMessage("*not sent*");
        (await SessionAsync(db)).Should().Be(before);
        (await db.Database.SqlQueryRaw<string>("SELECT setting AS \"Value\" FROM pg_settings WHERE name = 'search_path'").ToListAsync())
            .Should().ContainSingle().Which.Should().Be("tenant_a", "reading pg_settings is allowed and shows the bound path");
    }
}
