using System.Data;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Data;
using Xunit;

namespace Pinotechrd.Security.Tests.Data;

/// <summary>
/// What the command interceptor does with SQL that changes the session: a batch that changes it and runs other statements is
/// refused before it runs; a statement that changes it on its own runs, and the connection is then refused for every later
/// EF command until it is closed and reopened. Runs on SQLite with an emulated session (see <see cref="PostgresLikeSession"/>),
/// so real SET, RESET and DISCARD statements are not executed here: a command that is "sent" fails inside SQLite with a
/// <see cref="SqliteException"/>, which is how these tests tell it from a refusal by the library.
/// </summary>
public class SessionChangeInterceptorTests
{
    // A statement SQLite can run and that moves the emulated server-side path.
    private const string MoveThePath = "SELECT set_config('search_path', 'tenant_b', false)";

    // ---- A session change mixed with other statements is refused before it runs --------------

    [Theory]
    [InlineData("SELECT set_config('search_path', 'tenant_b', false); SELECT 1")]
    [InlineData("SELECT 1; SELECT set_config('search_path', 'tenant_b', false)")]
    [InlineData("SELECT set_config('search_path', 'tenant_b', false);\nSELECT 1")]
    public void ExecuteSql_ShouldRefuseTheWholeBatchBeforeItRuns_WhenItChangesTheSessionAndRunsOtherStatements(string batch)
    {
        using var session = new PostgresLikeSession();
        using var db = SearchPathContexts.Create(session, "a");
        db.Database.OpenConnection();

        var act = () => db.Database.ExecuteSqlRaw(batch);

        act.Should().Throw<InvalidOperationException>().WithMessage("*changes the session*other statements*");
        session.Path.Should().Be("tenant_a", "the refused batch never reached the server");
    }

    [Fact]
    public void ExecuteSql_ShouldKeepTheConnectionUsable_AfterRefusingAMixedBatch()
    {
        using var session = new PostgresLikeSession();
        using var db = SearchPathContexts.Create(session, "a");
        db.Database.OpenConnection();
        var refused = () => db.Database.ExecuteSqlRaw(MoveThePath + "; SELECT 1");
        refused.Should().Throw<InvalidOperationException>();

        SearchPathContexts.CurrentPath(db).Should().Be("tenant_a");
    }

    [Fact]
    public async Task ExecuteSqlAsync_ShouldRefuseAMixedBatchBeforeItRuns()
    {
        using var session = new PostgresLikeSession();
        await using var db = SearchPathContexts.Create(session, "a");
        await db.Database.OpenConnectionAsync();

        var act = () => db.Database.ExecuteSqlRawAsync(MoveThePath + "; SELECT 1");

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*other statements*");
        session.Path.Should().Be("tenant_a");
    }

    [Theory]
    [InlineData("SET search_path TO tenant_b; SELECT 1")]
    [InlineData("SET ROLE r; SELECT 1")]
    [InlineData("RESET ALL; SELECT 1")]
    [InlineData("DISCARD ALL; SELECT 1")]
    [InlineData("SET SESSION AUTHORIZATION u; SELECT 1")]
    public void ExecuteSql_ShouldRefuseMixedBatchesOfEveryKind_WithoutSendingThemToTheDatabase(string batch)
    {
        using var session = new PostgresLikeSession();
        using var db = SearchPathContexts.Create(session, "a");
        db.Database.OpenConnection();

        var act = () => db.Database.ExecuteSqlRaw(batch);

        // InvalidOperationException from the library; a SqliteException would mean the text was sent to the database.
        act.Should().Throw<InvalidOperationException>().WithMessage("*other statements*");
    }

    [Fact]
    public void SqlQuery_ShouldRefuseAMixedBatch_OnTheReaderPathToo()
    {
        using var session = new PostgresLikeSession();
        using var db = SearchPathContexts.Create(session, "a");
        db.Database.OpenConnection();

        var act = () => db.Database.SqlQueryRaw<string>("SELECT set_config('search_path', 'tenant_b', false) AS Value; SELECT 'x' AS Value").ToList();

        act.Should().Throw<InvalidOperationException>().WithMessage("*other statements*");
        session.Path.Should().Be("tenant_a");
    }

    // ---- A session change is always refused before it is sent ---------------------------------

    private const string NotSent = "*changes the session*not sent*";

    [Fact]
    public void ExecuteSql_ShouldRefuseALoneSessionChangeBeforeSendingIt_AndKeepTheConnectionBound()
    {
        using var session = new PostgresLikeSession();
        using var db = SearchPathContexts.Create(session, "a");
        db.Database.OpenConnection();

        var act = () => db.Database.ExecuteSqlRaw(MoveThePath);

        act.Should().Throw<InvalidOperationException>().WithMessage(NotSent);
        session.Path.Should().Be("tenant_a", "the statement was never sent");
        SearchPathContexts.CurrentPath(db).Should().Be("tenant_a", "the next command succeeds on the bound tenant");
    }

    [Fact]
    public void ExecuteSql_ShouldRefuseALoneSessionChangeWithATrailingSemicolon()
    {
        using var session = new PostgresLikeSession();
        using var db = SearchPathContexts.Create(session, "a");
        db.Database.OpenConnection();

        var act = () => db.Database.ExecuteSqlRaw(MoveThePath + ";");

        act.Should().Throw<InvalidOperationException>().WithMessage(NotSent);
        session.Path.Should().Be("tenant_a");
        SearchPathContexts.CurrentPath(db).Should().Be("tenant_a");
    }

    [Fact]
    public void ExecuteSql_ShouldRefuseASessionChangeThatTheServerCouldNotRunEither_WithoutSendingIt()
    {
        using var session = new PostgresLikeSession();
        using var db = SearchPathContexts.Create(session, "a");
        db.Database.OpenConnection();

        // SQLite cannot run SET: a SqliteException would mean the text was sent. The library must refuse it first.
        var act = () => db.Database.ExecuteSqlRaw("SET search_path TO tenant_b");

        act.Should().Throw<InvalidOperationException>().WithMessage(NotSent);
        SearchPathContexts.CurrentPath(db).Should().Be("tenant_a");
    }

    [Fact]
    public async Task ExecuteSqlAsync_ShouldRefuseALoneSessionChange_AndTheNextCommandSucceeds()
    {
        using var session = new PostgresLikeSession();
        await using var db = SearchPathContexts.Create(session, "a");
        await db.Database.OpenConnectionAsync();

        var act = () => db.Database.ExecuteSqlRawAsync(MoveThePath);

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage(NotSent);
        session.Path.Should().Be("tenant_a");
        (await db.Database.SqlQueryRaw<string>("SELECT current_setting('search_path') AS Value").ToListAsync()).Should().Equal("tenant_a");
    }

    [Fact]
    public void Refusal_ShouldNameTheKindOfChange_InTheMessage()
    {
        using var session = new PostgresLikeSession();
        using var db = SearchPathContexts.Create(session, "a");
        db.Database.OpenConnection();

        var act = () => db.Database.ExecuteSqlRaw("DISCARD ALL");

        act.Should().Throw<InvalidOperationException>().WithMessage("*DISCARD*not sent*");
    }

    [Fact]
    public void Refusal_ShouldKeepTheTransactionUsable()
    {
        using var session = new PostgresLikeSession();
        using var db = SearchPathContexts.Create(session, "a");
        using var transaction = db.Database.BeginTransaction();

        var act = () => db.Database.ExecuteSqlRaw(MoveThePath);

        act.Should().Throw<InvalidOperationException>().WithMessage(NotSent);
        SearchPathContexts.CurrentPath(db).Should().Be("tenant_a");
    }

    [Fact]
    public void ClosingAndReopeningTheConnectionByHand_ShouldBeRefused_AndAFreshContextWorksAfterwards()
    {
        using var session = new PostgresLikeSession();
        using (var db = SearchPathContexts.Create(session, "a"))
        {
            db.Database.OpenConnection();
            SearchPathContexts.CurrentPath(db).Should().Be("tenant_a");

            var connection = db.Database.GetDbConnection();
            connection.Close();
            connection.Open();

            var act = () => SearchPathContexts.CurrentPath(db);
            act.Should().Throw<InvalidOperationException>().WithMessage("*not bound*");
            connection.Close();
        }

        using var fresh = SearchPathContexts.Create(session, "a");
        SearchPathContexts.CurrentPath(fresh).Should().Be("tenant_a");
    }

    [Fact]
    public void ClosingTheConnectionByHand_ThenLettingEfOpenItAgain_ShouldBindTheTenantAgain()
    {
        using var session = new PostgresLikeSession();
        using var db = SearchPathContexts.Create(session, "a");
        db.Database.OpenConnection();
        db.Database.GetDbConnection().Close();

        db.Database.OpenConnection();

        SearchPathContexts.CurrentPath(db).Should().Be("tenant_a");
    }

    [Fact]
    public void Refusal_ShouldNotAffectAnotherContextThatOpensItsOwnConnection()
    {
        using var first = new PostgresLikeSession();
        using var second = new PostgresLikeSession();
        using var refusedDb = SearchPathContexts.Create(first, "a");
        using var otherDb = SearchPathContexts.Create(second, "a");
        refusedDb.Database.OpenConnection();
        var act = () => refusedDb.Database.ExecuteSqlRaw(MoveThePath);
        act.Should().Throw<InvalidOperationException>();

        SearchPathContexts.CurrentPath(otherDb).Should().Be("tenant_a");
    }

    [Theory]
    [InlineData("off")]
    [InlineData("OFF")]
    [InlineData("garbage")]
    public void Open_ShouldBeRefusedAndLeaveTheConnectionClosed_WhenStandardConformingStringsIsNotOn(string value)
    {
        using var session = new PostgresLikeSession { ConformingStrings = value };
        using var db = SearchPathContexts.Create(session, "a");

        var act = () => db.Database.OpenConnection();

        act.Should().Throw<InvalidOperationException>().WithMessage("*standard_conforming_strings*");
        session.Connection.State.Should().Be(ConnectionState.Closed);
    }

    [Theory]
    [InlineData("on")]
    [InlineData("ON")]
    [InlineData(null)]
    public void Open_ShouldBind_WhenStandardConformingStringsIsOnOrUnknown(string? value)
    {
        // NULL is accepted on purpose: only a stand-in that is not PostgreSQL answers it.
        using var session = new PostgresLikeSession { ConformingStrings = value };
        using var db = SearchPathContexts.Create(session, "a");

        SearchPathContexts.CurrentPath(db).Should().Be("tenant_a");
    }

    [Fact]
    public void SharedSchemaFallback_ShouldBeRefusedAtConstruction_InSearchPathMode()
    {
        using var session = new PostgresLikeSession();
        var builder = new DbContextOptionsBuilder<SecDb>().UseSqlite(session.Connection);
        builder.UsePinotechrdSecurity(o => o.TenantSchemaMode = TenantSchemaMode.SearchPath);
        var tenancy = new Pinotechrd.Security.Tenancy.TenantResolutionOptions { UseSharedSchemaWhenNoTenant = true };

        var act = () => new SecDb(builder.Options, new Pinotechrd.Security.Tenancy.DbSchemaProvider(SecDbFactory.Tenant(null), tenancy));

        act.Should().Throw<InvalidOperationException>().WithMessage("*UseSharedSchemaWhenNoTenant*");
    }

    // ---- Statements that must keep working ---------------------------------------------------

    [Theory]
    [InlineData("SELECT current_setting('search_path')")]
    [InlineData("SELECT 1; SELECT 2")]
    [InlineData("SELECT 'a' AS reset_token")]
    [InlineData("SELECT set_config('app.user_id', 'u1', false)")]
    public void ExecuteSql_ShouldRunOrdinaryStatements_AndLeaveTheConnectionBound(string sql)
    {
        using var session = new PostgresLikeSession();
        using var db = SearchPathContexts.Create(session, "a");
        db.Database.OpenConnection();

        db.Database.ExecuteSqlRaw(sql);

        SearchPathContexts.CurrentPath(db).Should().Be("tenant_a");
    }

    [Fact]
    public void SqlQuery_ShouldRunAReadOfTheSearchPath_ManyTimes()
    {
        using var session = new PostgresLikeSession();
        using var db = SearchPathContexts.Create(session, "a");
        db.Database.OpenConnection();

        for (var i = 0; i < 5; i++)
        {
            SearchPathContexts.CurrentPath(db).Should().Be("tenant_a", $"read {i}");
        }
    }
}
