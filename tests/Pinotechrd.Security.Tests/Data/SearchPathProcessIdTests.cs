using System.Data;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
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
        }

        public int ProbeCalls { get; private set; }

        public InvalidOperationException? Failure { get; set; }

        public int ReadProcessId() => Failure is { } failure ? throw failure : 4242;
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
    private sealed class WithoutProcessId(string file) : FakeConnection(file) { }

    private static SecDb Create(SqliteConnection connection)
    {
        var builder = new DbContextOptionsBuilder<SecDb>().UseSqlite(connection);
        builder.UsePinotechrdSecurity(o => o.TenantSchemaMode = TenantSchemaMode.SearchPath);
        return new SecDb(builder.Options, new DbSchemaProvider(SecDbFactory.Tenant("a")));
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

    [Fact]
    public void Scalar_ShouldBeRefusedAndNotSent_WhenProcessIdCannotBeReadAfterBinding()
    {
        using var connection = new ThrowsAfterScalar(_file);
        using var db = Create(connection);
        db.Database.OpenConnection();
        var original = connection.Failure = Boom();

        // EF sends scalar commands through its own ExecuteScalar path: a SqlQuery with Count/Single-style composition.
        AssertRefused(() => db.Database.SqlQueryRaw<int>("SELECT probe() AS Value").Count(), connection, original);
    }

    [Fact]
    public async Task ScalarAsync_ShouldBeRefusedAndNotSent_WhenProcessIdCannotBeReadAfterBinding()
    {
        await using var connection = new ThrowsAfterScalarAsync(_file);
        await using var db = Create(connection);
        await db.Database.OpenConnectionAsync();
        var original = connection.Failure = Boom();

        var act = () => db.Database.SqlQueryRaw<int>("SELECT probe() AS Value").CountAsync();

        (await act.Should().ThrowAsync<InvalidOperationException>().Where(e => e.Message == ExpectedMessage))
            .And.InnerException.Should().BeSameAs(original);
        connection.ProbeCalls.Should().Be(0);
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
