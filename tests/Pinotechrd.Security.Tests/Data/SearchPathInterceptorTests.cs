using System.Collections.Concurrent;
using System.Data;
using System.Transactions;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Data;

/// <summary>
/// The search_path interceptors of <c>TenantSchemaMode.SearchPath</c>.
///
/// PostgreSQL is not available in this test project (no Npgsql or Testcontainers package, and no new dependency was
/// authorized), so the session variable is emulated on SQLite: <c>set_config</c> and <c>current_setting</c> are registered as
/// SQLite functions, and the "session" survives Close and Open of the same connection object, like a pooled connection.
/// What these tests prove is the logic of the interceptors. They do not prove Npgsql pooling, its TransactionScope
/// enlistment, or the behavior of real SET, RESET ALL and DISCARD ALL statements.
/// </summary>
public sealed class SearchPathInterceptorTests : IDisposable
{
    private const string DefaultPath = "\"$user\", public";
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "pinotechrd-search-path-" + Guid.NewGuid().ToString("N"));
    private readonly List<FakePostgresSession> _sessions = [];

    public SearchPathInterceptorTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        foreach (var session in _sessions) session.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_directory, recursive: true); } catch (IOException) { }
    }

    /// <summary>One physical connection with a server-side session variable that outlives Close and Open.</summary>
    private sealed class FakePostgresSession : IDisposable
    {
        public FakePostgresSession(string file)
        {
            Connection = new SqliteConnection($"Data Source={file};Pooling=False");
            Connection.CreateFunction("set_config", (string name, string value, long isLocal) =>
            {
                lock (Gate)
                {
                    SetConfigCalls++;
                    if (FailSetConfig) throw new InvalidOperationException("set_config failed");
                    if (name == "search_path") Path = value;
                    return value;
                }
            });
            Connection.CreateFunction("current_setting", (string name) =>
            {
                lock (Gate) return name == "search_path" ? CurrentSettingOverride ?? Path : null;
            });
        }

        public object Gate { get; } = new();

        public SqliteConnection Connection { get; }

        public string Path { get; set; } = DefaultPath;

        public int SetConfigCalls { get; private set; }

        public bool FailSetConfig { get; set; }

        public string? CurrentSettingOverride { get; set; }

        public void Dispose() => Connection.Dispose();
    }

    private FakePostgresSession NewSession()
    {
        var session = new FakePostgresSession(Path.Combine(_directory, "db-" + Guid.NewGuid().ToString("N") + ".db"));
        _sessions.Add(session);
        return session;
    }

    private static TenantContext TenantOf(string? id) => SecDbFactory.Tenant(id);

    private static SecDb Context(FakePostgresSession session, TenantContext tenant, Action<PinotechrdSecurityModelOptions>? configure = null)
    {
        var builder = new DbContextOptionsBuilder<SecDb>().UseSqlite(session.Connection);
        builder.UsePinotechrdSecurity(o =>
        {
            o.TenantSchemaMode = TenantSchemaMode.SearchPath;
            configure?.Invoke(o);
        });
        return new SecDb(builder.Options, new DbSchemaProvider(tenant));
    }

    private static string CurrentPath(SecDb db) =>
        db.Database.SqlQueryRaw<string>("SELECT current_setting('search_path') AS Value").AsEnumerable().Single();

    // ---- Constructor guard -------------------------------------------------------------------

    private static DbContextOptionsBuilder<SecDb> BuilderWithoutInterceptors(Action<PinotechrdSecurityModelOptions> configure)
    {
        var original = new DbContextOptionsBuilder<SecDb>().UseSqlite("Data Source=:memory:");
        original.UsePinotechrdSecurity(configure);

        // Somebody rebuilt the options from the extensions and dropped the core ones, interceptors included.
        var rebuilt = new DbContextOptionsBuilder<SecDb>();
        foreach (var extension in original.Options.Extensions.Where(e => e is not CoreOptionsExtension))
        {
            ((IDbContextOptionsBuilderInfrastructure)rebuilt).AddOrUpdateExtension(extension);
        }

        rebuilt.Options.FindExtension<CoreOptionsExtension>()?.Interceptors.Should().BeNullOrEmpty();
        return rebuilt;
    }

    [Fact]
    public void Constructor_ShouldThrow_WhenSearchPathModeHasNoInterceptorsAndNoOptOut()
    {
        var builder = BuilderWithoutInterceptors(o => o.TenantSchemaMode = TenantSchemaMode.SearchPath);

        var act = () => new SecDb(builder.Options, new DbSchemaProvider(TenantOf("a")));

        act.Should().Throw<InvalidOperationException>().WithMessage("*search_path*");
    }

    [Fact]
    public void Constructor_ShouldSucceed_WhenTheApplicationTakesResponsibility()
    {
        var builder = new DbContextOptionsBuilder<SecDb>().UseSqlite("Data Source=:memory:");
        builder.UsePinotechrdSecurity(o =>
        {
            o.TenantSchemaMode = TenantSchemaMode.SearchPath;
            o.ApplicationTakesResponsibilityForSearchPath = true;
        });

        var act = () => new SecDb(builder.Options, new DbSchemaProvider(TenantOf("a")));

        act.Should().NotThrow();
        builder.Options.FindExtension<CoreOptionsExtension>()!.Interceptors.Should().BeNullOrEmpty("the opt-out installs nothing");
    }

    [Fact]
    public void Constructor_ShouldSucceed_WhenUsePinotechrdSecurityInstalledTheInterceptors()
    {
        var builder = new DbContextOptionsBuilder<SecDb>().UseSqlite("Data Source=:memory:");
        builder.UsePinotechrdSecurity(o => o.TenantSchemaMode = TenantSchemaMode.SearchPath);

        var act = () => new SecDb(builder.Options, new DbSchemaProvider(TenantOf("a")));

        act.Should().NotThrow();
        builder.Options.FindExtension<CoreOptionsExtension>()!.Interceptors.Should().HaveCount(2);
    }

    [Fact]
    public void Constructor_ShouldNotNeedInterceptors_InSchemaPerTenantMode()
    {
        var builder = BuilderWithoutInterceptors(_ => { });

        var act = () => new SecDb(builder.Options, new DbSchemaProvider(TenantOf("a")));

        act.Should().NotThrow();
    }

    [Fact]
    public void Constructor_ShouldRefuseAPrebuiltModel_InSchemaPerTenantMode()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var source = SecDbFactory.Create(connection, "a");
        var model = source.Model;
        var builder = new DbContextOptionsBuilder<SecDb>().UseSqlite(connection).UseModel(model);
        builder.UsePinotechrdSecurity();

        var act = () => new SecDb(builder.Options, new DbSchemaProvider(TenantOf("a")));

        act.Should().Throw<InvalidOperationException>().WithMessage("*UseModel*");
    }

    [Fact]
    public void Constructor_ShouldAcceptAPrebuiltModel_InSearchPathMode()
    {
        using var connection = SecDbFactory.OpenMemory();
        using var source = SecDbFactory.Create(connection, "a", configure: o => o.TenantSchemaMode = TenantSchemaMode.SearchPath);
        var model = source.Model;
        var builder = new DbContextOptionsBuilder<SecDb>().UseSqlite(connection).UseModel(model);
        builder.UsePinotechrdSecurity(o => o.TenantSchemaMode = TenantSchemaMode.SearchPath);

        var act = () => new SecDb(builder.Options, new DbSchemaProvider(TenantOf("a")));

        act.Should().NotThrow();
    }

    // ---- Binding -----------------------------------------------------------------------------

    [Theory]
    [InlineData("a", "tenant_a")]
    [InlineData("acme-1", "tenant_acme_1")]
    public void Open_ShouldBindSearchPathToExactlyTheTenantSchema(string tenantId, string schema)
    {
        var session = NewSession();
        using var db = Context(session, TenantOf(tenantId));

        CurrentPath(db).Should().Be(schema);
        session.SetConfigCalls.Should().BeGreaterThan(0);
    }

    [Fact]
    public void Open_ShouldBeRefused_WhenNoTenantIsResolved()
    {
        var session = NewSession();
        using var db = Context(session, TenantOf(null));

        var act = () => db.Database.OpenConnection();

        act.Should().Throw<InvalidOperationException>();
        session.SetConfigCalls.Should().Be(0, "nothing was sent to the server");
        session.Path.Should().Be(DefaultPath);
        session.Connection.State.Should().Be(ConnectionState.Closed);
    }

    [Fact]
    public void Query_ShouldBeRefused_WhenNoTenantIsResolved()
    {
        var session = NewSession();
        using var db = Context(session, TenantOf(null));

        var act = () => db.Tenants.ToList();

        act.Should().Throw<InvalidOperationException>();
        session.Connection.State.Should().Be(ConnectionState.Closed);
    }

    [Fact]
    public void Open_ShouldThrowInsideATransactionScope_AndTheNextQueryOutsideItRunsInTheTenantSchema()
    {
        var session = NewSession();
        using (var db = Context(session, TenantOf("a")))
        using (new TransactionScope())
        {
            var act = () => db.Database.OpenConnection();

            act.Should().Throw<InvalidOperationException>().WithMessage("*TransactionScope*");
            session.Connection.State.Should().Be(ConnectionState.Closed, "a refused bind closes the connection");
        }

        using var next = Context(session, TenantOf("a"));
        CurrentPath(next).Should().Be("tenant_a");
    }

    [Fact]
    public async Task OpenAsync_ShouldThrowInsideATransactionScope_AndTheNextQueryOutsideItRunsInTheTenantSchema()
    {
        var session = NewSession();
        using (var db = Context(session, TenantOf("a")))
        using (new TransactionScope(TransactionScopeAsyncFlowOption.Enabled))
        {
            var act = () => db.Database.OpenConnectionAsync();

            await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*TransactionScope*");
        }

        using var next = Context(session, TenantOf("a"));
        CurrentPath(next).Should().Be("tenant_a");
    }

    [Fact]
    public void FirstCommand_ShouldThrow_WhenTheApplicationOpenedTheConnectionItself()
    {
        var session = NewSession();
        session.Connection.Open();
        using var db = Context(session, TenantOf("a"));

        var act = () => db.Tenants.ToList();

        act.Should().Throw<InvalidOperationException>().WithMessage("*not bound*");
        session.Path.Should().Be(DefaultPath, "EF never bound a connection it did not open");
    }

    [Fact]
    public void Command_ShouldThrow_WhenTheTenantChangesAfterTheConnectionWasBound()
    {
        var session = NewSession();
        var tenant = TenantOf("a");
        using var db = Context(session, tenant);
        db.Database.OpenConnection();
        CurrentPath(db).Should().Be("tenant_a");

        tenant.SetTenant("b");
        var act = () => CurrentPath(db);

        act.Should().Throw<InvalidOperationException>().WithMessage("*not bound*");
    }

    [Fact]
    public void Open_ShouldLeaveTheConnectionClosed_WhenBindingFails()
    {
        var session = NewSession();
        session.FailSetConfig = true;
        using var db = Context(session, TenantOf("a"));

        var act = () => db.Database.OpenConnection();

        act.Should().Throw<Exception>();
        session.Connection.State.Should().Be(ConnectionState.Closed);
    }

    [Fact]
    public void Open_ShouldLeaveTheConnectionClosedAndRefuseCommands_WhenTheServerReportsAnotherPath()
    {
        var session = NewSession();
        session.CurrentSettingOverride = "\"$user\", public";
        using var db = Context(session, TenantOf("a"));

        var open = () => db.Database.OpenConnection();

        open.Should().Throw<InvalidOperationException>().WithMessage("*could not be bound*");
        session.Connection.State.Should().Be(ConnectionState.Closed);
    }

    [Fact]
    public void Open_ShouldNotBind_WhenTheApplicationTakesResponsibility()
    {
        var session = NewSession();
        using var db = Context(session, TenantOf("a"), o => o.ApplicationTakesResponsibilityForSearchPath = true);

        CurrentPath(db).Should().Be(DefaultPath);
        session.SetConfigCalls.Should().Be(0);
    }

    // ---- Alternating tenants on shared connections -------------------------------------------

    [Fact]
    public void AlternatingTenants_ShouldNeverCross_WhenAConnectionIsReusedSequentially()
    {
        var session = NewSession();

        for (var i = 0; i < 20; i++)
        {
            var tenant = i % 2 == 0 ? "a" : "b";
            using var db = Context(session, TenantOf(tenant));
            CurrentPath(db).Should().Be("tenant_" + tenant, $"iteration {i}");
        }
    }

    [Fact]
    public async Task AlternatingTenants_ShouldNeverCross_WhenFortyRequestsShareASmallPoolInParallel()
    {
        var pool = new ConcurrentBag<FakePostgresSession>(Enumerable.Range(0, 3).Select(_ => NewSession()));
        using var gate = new SemaphoreSlim(3);
        var wrong = new ConcurrentBag<string>();

        await Task.WhenAll(Enumerable.Range(0, 40).Select(i => Task.Run(async () =>
        {
            await gate.WaitAsync();
            pool.TryTake(out var session);
            try
            {
                var tenant = i % 2 == 0 ? "a" : "b";
                using var db = Context(session!, TenantOf(tenant));
                for (var q = 0; q < 3; q++)
                {
                    var path = CurrentPath(db);
                    if (path != "tenant_" + tenant) wrong.Add($"{tenant}:{path}");
                }
            }
            finally
            {
                pool.Add(session!);
                gate.Release();
            }
        })));

        wrong.Should().BeEmpty();
    }

    // ---- User SQL that changes the path ------------------------------------------------------

    // A statement that changes the path is refused before it is sent: the session path is unchanged and the next command
    // on the same connection runs on the bound tenant.
    [Theory]
    [InlineData("SELECT set_config('search_path', 'tenant_b', false)")]
    [InlineData("SELECT set_config('search_path', '\"$user\", public', false)")]
    public void AfterUserSqlTriedToChangeThePath_TheNextEfCommandOnTheSameConnection_ShouldRunOnTheBoundTenant(string sql)
    {
        var session = NewSession();
        using var db = Context(session, TenantOf("a"));
        db.Database.OpenConnection();
        CurrentPath(db).Should().Be("tenant_a");

        var act = () => db.Database.ExecuteSqlRaw(sql);

        act.Should().Throw<InvalidOperationException>().WithMessage("*changes the session*not sent*");
        session.Path.Should().Be("tenant_a");
        CurrentPath(db).Should().Be("tenant_a");
    }

    [Fact]
    public void AfterUserSqlTriedToChangeThePath_TheNextEfCommandInsideATransaction_ShouldRunOnTheBoundTenant()
    {
        var session = NewSession();
        using var db = Context(session, TenantOf("a"));
        using var transaction = db.Database.BeginTransaction();

        var act = () => db.Database.ExecuteSqlRaw("SELECT set_config('search_path', 'tenant_b', false)");

        act.Should().Throw<InvalidOperationException>().WithMessage("*not sent*");
        CurrentPath(db).Should().Be("tenant_a");
    }
}
