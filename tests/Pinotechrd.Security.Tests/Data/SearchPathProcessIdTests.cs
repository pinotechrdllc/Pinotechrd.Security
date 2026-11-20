using System.Data;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Tenancy;
using Xunit;

namespace Pinotechrd.Security.Tests.Data;

/// <summary>
/// The search_path binding reads the provider's <c>ProcessID</c> to prove that a command runs on the session it was bound
/// on. When that read throws, the library must fail closed instead of skipping the check. The provider is stood in by
/// SQLite connections that expose a public <c>int ProcessID</c> the test controls. The library caches the property lookup per
/// connection type, so every scenario uses its own connection type.
/// </summary>
public sealed class SearchPathProcessIdTests : IDisposable
{
    private const string ExpectedMessage =
        "The connection's database session id (ProcessID) could not be read, so the session bound to the tenant schema cannot be verified.";

    private readonly string _file = Path.Combine(Path.GetTempPath(), "pinotechrd-pid-" + Guid.NewGuid().ToString("N") + ".db");

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { File.Delete(_file); } catch (IOException) { }
    }

    /// <summary>SQLite connection with the server-side functions the binding needs and a probe that counts commands that reach the engine.</summary>
    private abstract class FakeConnection : SqliteConnection
    {
        private string _path = "\"$user\", public";

        protected FakeConnection(string file) : base($"Data Source={file};Pooling=False")
        {
            CreateFunction("set_config", (string name, string value, long isLocal) =>
            {
                if (name == "search_path") _path = value;
                return value;
            });
            CreateFunction("current_setting", (string name) => name == "search_path" ? _path : null);
            CreateFunction("probe", () => ++ProbeCalls);
            // A direct connection: the server's process id is the one the client was given, unless a test sets ServerPid.
            CreateFunction("pg_backend_pid", () => ServerPid ?? Pid);
        }

        /// <summary>What pg_backend_pid() answers when it differs from ProcessID, as behind a connection pooler.</summary>
        public int? ServerPid { get; set; }

        public int ProbeCalls { get; private set; }

        public InvalidOperationException? Failure { get; set; }

        public int ReadProcessId() => Failure is { } failure ? throw failure : Pid;

        public int Pid { get; set; } = 4242;
    }

    private sealed class ThrowsOnBindSync(string file) : FakeConnection(file) { public int ProcessID => ReadProcessId(); }
    private sealed class ThrowsOnBindAsync(string file) : FakeConnection(file) { public int ProcessID => ReadProcessId(); }
    private sealed class ThrowsAfterReader(string file) : FakeConnection(file) { public int ProcessID => ReadProcessId(); }
    private sealed class ThrowsAfterReaderAsync(string file) : FakeConnection(file) { public int ProcessID => ReadProcessId(); }
    private sealed class ThrowsAfterNonQuery(string file) : FakeConnection(file) { public int ProcessID => ReadProcessId(); }
    private sealed class ThrowsAfterNonQueryAsync(string file) : FakeConnection(file) { public int ProcessID => ReadProcessId(); }
    private sealed class ThrowsAfterScalar(string file) : FakeConnection(file) { public int ProcessID => ReadProcessId(); }
    private sealed class ThrowsAfterScalarAsync(string file) : FakeConnection(file) { public int ProcessID => ReadProcessId(); }
    private sealed class StableProcessId(string file) : FakeConnection(file) { public int ProcessID => ReadProcessId(); }
    private sealed class ChangedSession(string file) : FakeConnection(file) { public int ProcessID => ReadProcessId(); }
    private sealed class WithoutProcessId(string file) : FakeConnection(file) { }
    private sealed class BehindPooler(string file) : FakeConnection(file) { public int ProcessID => ReadProcessId(); }
    private sealed class BehindPoolerAsync(string file) : FakeConnection(file) { public int ProcessID => ReadProcessId(); }
    private sealed class BehindSessionPooler(string file) : FakeConnection(file) { public int ProcessID => ReadProcessId(); }
    private sealed class WithoutProcessIdBehindPooler(string file) : FakeConnection(file) { }

    private sealed class ScalarRecorder : DbCommandInterceptor
    {
        public int Calls { get; private set; }

        public override InterceptionResult<object> ScalarExecuting(System.Data.Common.DbCommand command, CommandEventData eventData, InterceptionResult<object> result)
        {
            Calls++;
            return result;
        }

        public override ValueTask<InterceptionResult<object>> ScalarExecutingAsync(System.Data.Common.DbCommand command, CommandEventData eventData, InterceptionResult<object> result, CancellationToken cancellationToken = default)
        {
            Calls++;
            return ValueTask.FromResult(result);
        }
    }

    private static SecDb Create(SqliteConnection connection, IInterceptor? extra = null, bool poolerInSessionMode = false)
    {
        var builder = new DbContextOptionsBuilder<SecDb>().UseSqlite(connection);
        if (extra != null) builder.AddInterceptors(extra);
        builder.UsePinotechrdSecurity(o =>
        {
            o.TenantSchemaMode = TenantSchemaMode.SearchPath;
            o.ConnectionPoolerUsesSessionMode = poolerInSessionMode;
        });
        return new SecDb(builder.Options, new DbSchemaProvider(SecDbFactory.Tenant("a")));
    }

    // ---- Connection pooler between the client and the server -------------------------------

    [Fact]
    public void Open_ShouldBeRefusedAndClosed_WhenAPoolerSitsBetweenTheClientAndTheServer()
    {
        using var connection = new BehindPooler(_file) { ServerPid = 90 };
        using var db = Create(connection);

        var act = () => db.Database.OpenConnection();

        act.Should().Throw<InvalidOperationException>().WithMessage("*connection pooler*ConnectionPoolerUsesSessionMode*");
        connection.State.Should().Be(ConnectionState.Closed);
    }

    [Fact]
    public async Task OpenAsync_ShouldBeRefusedAndClosed_WhenAPoolerSitsBetweenTheClientAndTheServer()
    {
        await using var connection = new BehindPoolerAsync(_file) { ServerPid = 90 };
        await using var db = Create(connection);

        var act = () => db.Database.OpenConnectionAsync();

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*connection pooler*ConnectionPoolerUsesSessionMode*");
        connection.State.Should().Be(ConnectionState.Closed);
    }

    [Fact]
    public void Open_ShouldBind_WhenTheProviderExposesNoProcessId_SoThePoolerCheckCannotRun()
    {
        // Best effort, by design: without a client process id there is nothing to compare the server's with.
        using var connection = new WithoutProcessIdBehindPooler(_file) { ServerPid = 90 };
        using var db = Create(connection);

        db.Database.OpenConnection();

        connection.State.Should().Be(ConnectionState.Open);
    }

    [Fact]
    public void Open_ShouldBind_WhenThePoolerIsDeclaredToRunInSessionMode()
    {
        using var connection = new BehindSessionPooler(_file) { ServerPid = 90 };
        using var db = Create(connection, poolerInSessionMode: true);

        db.Database.OpenConnection();

        connection.State.Should().Be(ConnectionState.Open);
        db.Database.SqlQueryRaw<long>(ProbeSql).AsEnumerable().Single().Should().Be(1);
    }

    private static InvalidOperationException Boom() => new("provider failure");

    // ---- Criterion 1: bind fails closed ----------------------------------------------------

    [Fact]
    public void Open_ShouldThrowAndCloseTheConnection_WhenProcessIdCannotBeReadWhileBinding()
    {
        using var connection = new ThrowsOnBindSync(_file);
        var original = Boom();
        connection.Failure = original;
        using var db = Create(connection);

        var act = () => db.Database.OpenConnection();

        act.Should().Throw<InvalidOperationException>()
            .Where(e => e.Message == ExpectedMessage)
            .And.InnerException.Should().BeSameAs(original);
        connection.State.Should().Be(ConnectionState.Closed);
    }

    [Fact]
    public async Task OpenAsync_ShouldThrowAndCloseTheConnection_WhenProcessIdCannotBeReadWhileBinding()
    {
        await using var connection = new ThrowsOnBindAsync(_file);
        var original = Boom();
        connection.Failure = original;
        await using var db = Create(connection);

        var act = () => db.Database.OpenConnectionAsync();

        (await act.Should().ThrowAsync<InvalidOperationException>().Where(e => e.Message == ExpectedMessage))
            .And.InnerException.Should().BeSameAs(original);
        connection.State.Should().Be(ConnectionState.Closed);
    }

    // ---- Criterion 2: commands on a bound connection fail closed ---------------------------

    private const string ProbeSql = "SELECT probe()";

    private static void AssertRefused(Action act, FakeConnection connection, Exception original)
    {
        act.Should().Throw<InvalidOperationException>()
            .Where(e => e.Message == ExpectedMessage)
            .And.InnerException.Should().BeSameAs(original);
        connection.ProbeCalls.Should().Be(0, "the command was refused before it was sent");
    }

    [Fact]
    public void Reader_ShouldBeRefusedAndNotSent_WhenProcessIdCannotBeReadAfterBinding()
    {
        using var connection = new ThrowsAfterReader(_file);
        using var db = Create(connection);
        db.Database.OpenConnection();
        var original = connection.Failure = Boom();

        AssertRefused(() => db.Database.SqlQueryRaw<int>("SELECT probe() AS Value").ToList(), connection, original);
    }

    [Fact]
    public async Task ReaderAsync_ShouldBeRefusedAndNotSent_WhenProcessIdCannotBeReadAfterBinding()
    {
        await using var connection = new ThrowsAfterReaderAsync(_file);
        await using var db = Create(connection);
        await db.Database.OpenConnectionAsync();
        var original = connection.Failure = Boom();

        var act = () => db.Database.SqlQueryRaw<int>("SELECT probe() AS Value").ToListAsync();

        (await act.Should().ThrowAsync<InvalidOperationException>().Where(e => e.Message == ExpectedMessage))
            .And.InnerException.Should().BeSameAs(original);
        connection.ProbeCalls.Should().Be(0);
    }

    [Fact]
    public void NonQuery_ShouldBeRefusedAndNotSent_WhenProcessIdCannotBeReadAfterBinding()
    {
        using var connection = new ThrowsAfterNonQuery(_file);
        using var db = Create(connection);
        db.Database.OpenConnection();
        var original = connection.Failure = Boom();

        AssertRefused(() => db.Database.ExecuteSqlRaw(ProbeSql), connection, original);
    }

    [Fact]
    public async Task NonQueryAsync_ShouldBeRefusedAndNotSent_WhenProcessIdCannotBeReadAfterBinding()
    {
        await using var connection = new ThrowsAfterNonQueryAsync(_file);
        await using var db = Create(connection);
        await db.Database.OpenConnectionAsync();
        var original = connection.Failure = Boom();

        var act = () => db.Database.ExecuteSqlRawAsync(ProbeSql);

        (await act.Should().ThrowAsync<InvalidOperationException>().Where(e => e.Message == ExpectedMessage))
            .And.InnerException.Should().BeSameAs(original);
        connection.ProbeCalls.Should().Be(0);
    }

    private static (IRelationalCommand Command, RelationalCommandParameterObject Parameters) BuildScalar(DbContext db)
    {
        var raw = db.GetService<IRawSqlCommandBuilder>().Build(ProbeSql);
        var parameters = new RelationalCommandParameterObject(
            db.GetService<IRelationalConnection>(),
            new Dictionary<string, object?>(),
            readerColumns: null,
            context: db,
            logger: db.GetService<IRelationalCommandDiagnosticsLogger>(),
            detailedErrorsEnabled: false);
        return (raw, parameters);
    }

    [Fact]
    public void Scalar_ShouldBeRefusedAndNotSent_WhenProcessIdCannotBeReadAfterBinding()
    {
        using var connection = new ThrowsAfterScalar(_file);
        var seen = new ScalarRecorder();
        using var db = Create(connection, seen);
        db.Database.OpenConnection();
        var original = connection.Failure = Boom();
        var (raw, parameters) = BuildScalar(db);

        AssertRefused(() => raw.ExecuteScalar(parameters), connection, original);
        seen.Calls.Should().Be(1, "the command went through ScalarExecuting");
    }

    [Fact]
    public async Task ScalarAsync_ShouldBeRefusedAndNotSent_WhenProcessIdCannotBeReadAfterBinding()
    {
        await using var connection = new ThrowsAfterScalarAsync(_file);
        var seen = new ScalarRecorder();
        await using var db = Create(connection, seen);
        await db.Database.OpenConnectionAsync();
        var original = connection.Failure = Boom();
        var (raw, parameters) = BuildScalar(db);

        var act = () => raw.ExecuteScalarAsync(parameters);

        (await act.Should().ThrowAsync<InvalidOperationException>().Where(e => e.Message == ExpectedMessage))
            .And.InnerException.Should().BeSameAs(original);
        connection.ProbeCalls.Should().Be(0);
        seen.Calls.Should().Be(1, "the command went through ScalarExecutingAsync");
    }

    [Fact]
    public void Scalar_ShouldRun_WhenProcessIdIsReadableAndUnchanged()
    {
        using var connection = new StableProcessId(_file);
        var seen = new ScalarRecorder();
        using var db = Create(connection, seen);
        db.Database.OpenConnection();
        var (raw, parameters) = BuildScalar(db);

        raw.ExecuteScalar(parameters).Should().NotBeNull();

        seen.Calls.Should().Be(1, "proves the recorder sits on the scalar path");
        connection.ProbeCalls.Should().Be(1);
    }

    // ---- The session changed after binding --------------------------------------------------

    [Fact]
    public void Command_ShouldBeRefusedAndNotSent_WhenProcessIdDiffersFromTheBoundSession()
    {
        using var connection = new ChangedSession(_file);
        using var db = Create(connection);
        db.Database.OpenConnection();
        connection.Pid = 9999;

        var act = () => db.Database.ExecuteSqlRaw(ProbeSql);

        act.Should().Throw<InvalidOperationException>().WithMessage("*database session changed*")
            .And.InnerException.Should().BeNull();
        connection.ProbeCalls.Should().Be(0, "the command was refused before it was sent");
    }

    // ---- Control: a readable ProcessID does not get in the way -----------------------------

    [Fact]
    public void Command_ShouldRun_WhenProcessIdIsReadableAndUnchanged()
    {
        using var connection = new StableProcessId(_file);
        using var db = Create(connection);
        db.Database.OpenConnection();

        db.Database.SqlQueryRaw<int>("SELECT probe() AS Value").ToList().Should().ContainSingle();
        connection.ProbeCalls.Should().Be(1);
    }

    // ---- Criterion 3: no ProcessID property -------------------------------------------------

    [Fact]
    public void OpenAndCommand_ShouldWork_WhenTheConnectionTypeHasNoProcessIdProperty()
    {
        using var connection = new WithoutProcessId(_file);
        using var db = Create(connection);

        var open = () => db.Database.OpenConnection();
        open.Should().NotThrow();

        db.Database.SqlQueryRaw<int>("SELECT probe() AS Value").ToList().Should().ContainSingle();
        connection.State.Should().Be(ConnectionState.Open);
    }
}
