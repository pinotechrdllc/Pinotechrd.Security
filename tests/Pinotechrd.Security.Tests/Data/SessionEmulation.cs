using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Tenancy;

namespace Pinotechrd.Security.Tests.Data;

/// <summary>
/// A SQLite connection that behaves like one pooled PostgreSQL session for the parts the search_path binding touches:
/// <c>set_config</c> and <c>current_setting</c> exist as SQL functions and the value survives Close and Open of the same
/// connection object. It cannot run PostgreSQL syntax (SET, RESET, DISCARD): such a command reaches SQLite and fails there
/// with a <see cref="SqliteException"/>, which tests use to tell "refused by the library" (InvalidOperationException) from
/// "sent to the server".
/// </summary>
internal sealed class PostgresLikeSession : IDisposable
{
    public const string DefaultPath = "\"$user\", public";

    private readonly string _file = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "pinotechrd-session-" + Guid.NewGuid().ToString("N") + ".db");
    private readonly object _gate = new();

    public PostgresLikeSession(string? connectionStringLabel = null)
    {
        Connection = new LabelledConnection($"Data Source={_file};Pooling=False", connectionStringLabel);
        Connection.CreateFunction("set_config", (string name, string value, long isLocal) =>
        {
            lock (_gate)
            {
                SetConfigCalls++;
                if (name == "search_path") Path = value;
                return value;
            }
        });
        Connection.CreateFunction("current_setting", (string name) =>
        {
            lock (_gate) return name == "search_path" ? Path : name == "standard_conforming_strings" ? ConformingStrings : null;
        });
    }

    /// <summary>The emulated server-side search_path of this session.</summary>
    public string Path { get; private set; } = DefaultPath;

    /// <summary>What current_setting('standard_conforming_strings') answers; null (the default) is what a non-PostgreSQL stand-in gives.</summary>
    public string? ConformingStrings { get; set; }

    public int SetConfigCalls { get; private set; }

    public SqliteConnection Connection { get; }

    /// <summary>Creates tables with plain SQL on a separate connection, so EF still opens its own connection.</summary>
    public void Execute(string sql)
    {
        using var other = new SqliteConnection($"Data Source={_file};Pooling=False");
        other.Open();
        using var command = other.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    public void Dispose()
    {
        Connection.Dispose();
        SqliteConnection.ClearAllPools();
        try { File.Delete(_file); } catch (IOException) { }
    }

    /// <summary>Reports a chosen connection string, so the library's connection-string rules can be driven without Npgsql.</summary>
    private sealed class LabelledConnection : SqliteConnection
    {
        private readonly string? _label;

        public LabelledConnection(string real, string? label) : base(real) => _label = label;

        [System.Diagnostics.CodeAnalysis.AllowNull]
        public override string ConnectionString
        {
            get => _label ?? base.ConnectionString;
            set => base.ConnectionString = value;
        }
    }
}

internal static class SearchPathContexts
{
    /// <summary>A security context in SearchPath mode bound to <paramref name="tenantId"/> over the emulated session.</summary>
    public static SecDb Create(PostgresLikeSession session, string? tenantId)
    {
        var builder = new DbContextOptionsBuilder<SecDb>().UseSqlite(session.Connection);
        builder.UsePinotechrdSecurity(o => o.TenantSchemaMode = TenantSchemaMode.SearchPath);
        return new SecDb(builder.Options, new DbSchemaProvider(SecDbFactory.Tenant(tenantId)));
    }

    public static string CurrentPath(DbContext db) =>
        db.Database.SqlQueryRaw<string>("SELECT current_setting('search_path') AS Value").AsEnumerable().Single();
}
