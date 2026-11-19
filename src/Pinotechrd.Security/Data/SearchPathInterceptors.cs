using System.Data;
using System.Data.Common;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using System.Transactions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Pinotechrd.Security.Data;

/// <summary>
/// Implemented by a context that can name the schema its connections must be bound to.
/// </summary>
internal interface ISearchPathTenantSource
{
    /// <summary>Schema of the resolved tenant; throws when no tenant is resolved.</summary>
    string ResolveSearchPathSchema();
}

/// <summary>
/// Binds PostgreSQL connections to the resolved tenant's schema with <c>set_config('search_path', ...)</c> and
/// verifies the binding before every command. Used by <see cref="TenantSchemaMode.SearchPath"/>.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item><description>The search path is the tenant schema alone; <c>public</c> is not appended, so a missing
/// tenant table can never resolve to a shared table.</description></item>
/// <item><description>After setting it, the value is read back; any failure closes the connection and throws.</description></item>
/// <item><description>Binding refuses to run inside an ambient <see cref="Transaction"/>: a connection that
/// enlists would run <c>set_config</c> inside that transaction, and a rollback would silently restore the
/// default path. Open the connection before entering the <see cref="TransactionScope"/>, or use
/// <c>Database.BeginTransaction</c>.</description></item>
/// <item><description>Every command EF Core sends checks that its connection was bound by this class to the
/// current tenant's schema on the same physical session; a connection opened, closed or reopened outside EF Core,
/// or a tenant changed after the connection
/// was opened, makes the command throw. Raw ADO.NET commands on the same connection are not checked.</description></item>
/// </list>
/// </remarks>
internal static partial class SearchPathBinder
{

    [GeneratedRegex("^[a-z_][a-z0-9_]{0,62}$", RegexOptions.CultureInvariant)]
    private static partial Regex SchemaPattern();

    public static string SchemaFor(DbContext? context)
    {
        if (context is not ISearchPathTenantSource source)
        {
            throw new InvalidOperationException("The search_path interceptors only work with PinotechrdSecurityDbContext.");
        }

        var schema = source.ResolveSearchPathSchema();
        if (!SchemaPattern().IsMatch(schema))
        {
            throw new InvalidOperationException("The tenant schema name is not a plain lower-case identifier.");
        }

        return schema;
    }

    public static void Bind(DbConnection connection, DbContext? context)
    {
        try
        {
            var schema = PrepareBind(connection, context);
            using (var set = CreateSetCommand(connection, schema))
            {
                set.ExecuteScalar();
            }

            using var verify = CreateVerifyCommand(connection);
            using (var reader = verify.ExecuteReader())
            {
                Record(connection, schema, ReadVerify(reader));
            }
        }
        catch
        {
            Forget(connection);
            connection.Close();
            throw;
        }
    }

    public static async Task BindAsync(DbConnection connection, DbContext? context, CancellationToken cancellationToken)
    {
        try
        {
            var schema = PrepareBind(connection, context);
            await using (var set = CreateSetCommand(connection, schema))
            {
                await set.ExecuteScalarAsync(cancellationToken);
            }

            await using var verify = CreateVerifyCommand(connection);
            await using (var reader = await verify.ExecuteReaderAsync(cancellationToken))
            {
                Record(connection, schema, ReadVerify(reader));
            }
        }
        catch
        {
            Forget(connection);
            await connection.CloseAsync();
            throw;
        }
    }

    public static void EnsureBound(DbCommand command, DbContext? context)
    {
        var connection = command.Connection
            ?? throw new InvalidOperationException("The command has no connection.");
        var schema = SchemaFor(context);
        if (!States.TryGetValue(connection, out var state) || state.Schema is not { } boundSchema)
        {
            throw new InvalidOperationException(
                "The connection is not bound to the current tenant's schema. Let EF Core open the connection " +
                "(do not open, close or reopen it yourself), and do not change the tenant after the context has opened it.");
        }

        if (state.ProcessId is { } boundProcess && ProcessIdOf(connection) is { } currentProcess && boundProcess != currentProcess)
        {
            throw new InvalidOperationException(
                "The connection's database session changed since it was bound to the tenant schema. Let EF Core open the connection.");
        }

        if (!string.Equals(boundSchema, schema, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The connection is not bound to the current tenant's schema: it was bound to another tenant. Do not change the tenant after the context has opened it.");
        }

        // A command that changes the search path, the role or the whole session state is refused before it runs.
        var change = SessionChangeDetector.Find(command.CommandText);
        if (change != null)
        {
            throw new InvalidOperationException(SessionChangeDetector.HasSeveralStatements(command.CommandText)
                ? $"This command changes the session ({change}) and runs other statements in the same batch; it was not sent. " +
                  "TenantSchemaMode.SearchPath refuses commands that change the search path, the role or the session state."
                : $"This command changes the session ({change}); it was not sent. " +
                  "TenantSchemaMode.SearchPath refuses commands that change the search path, the role or the session state.");
        }
    }

    public static void Forget(DbConnection connection)
    {
        if (States.TryGetValue(connection, out var state)) state.Schema = null;
    }

    /// <summary>
    /// Binding of one <see cref="DbConnection"/> object. Created once per connection object, with a
    /// <see cref="DbConnection.StateChange"/> handler that forgets the binding as soon as the connection is closed or
    /// broken, whoever closes it, so a connection reopened outside EF Core is never trusted.
    /// </summary>
    private sealed class BindingState
    {
        public volatile string? Schema;
        public int? ProcessId;
    }

    private static readonly ConditionalWeakTable<DbConnection, BindingState> States = new();

    private static BindingState StateFor(DbConnection connection) => States.GetValue(connection, c =>
    {
        var state = new BindingState();
        c.StateChange += (_, e) =>
        {
            if (e.CurrentState is ConnectionState.Closed or ConnectionState.Broken) state.Schema = null;
        };
        return state;
    });

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<Type, System.Reflection.PropertyInfo?> ProcessIdProperties = new();

    /// <summary>
    /// The server process id of the physical session (Npgsql's <c>ProcessID</c>, read on the client without a round trip),
    /// or <see langword="null"/> when the provider does not expose one or the connection is not open.
    /// </summary>
    /// <exception cref="InvalidOperationException">The provider exposes <c>ProcessID</c> but reading it threw; the
    /// provider's exception is the <see cref="Exception.InnerException"/>. The session cannot be verified, so the
    /// caller fails closed instead of skipping the session-identity check.</exception>
    private static int? ProcessIdOf(DbConnection connection)
    {
        var property = ProcessIdProperties.GetOrAdd(connection.GetType(), t => t.GetProperty("ProcessID", typeof(int)));
        if (property == null || connection.State != ConnectionState.Open) return null;
        try
        {
            return (int?)property.GetValue(connection);
        }
        catch (System.Reflection.TargetInvocationException ex)
        {
            throw new InvalidOperationException(
                "The connection's database session id (ProcessID) could not be read, so the session bound to the tenant schema cannot be verified.",
                ex.InnerException ?? ex);
        }
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, string?> ConnectionStringProblems = new(StringComparer.Ordinal);

    /// <summary>
    /// Refuses connection settings under which a bound session path cannot be trusted: multiplexing (commands of
    /// one logical connection spread over several physical ones), no reset on close, and a default search path set
    /// by the connection string or its options. Checked once per connection string.
    /// </summary>
    private static void EnsureSupportedConnection(DbConnection connection)
    {
        var problem = ConnectionStringProblems.GetOrAdd(connection.ConnectionString ?? string.Empty, AnalyzeConnectionString);
        if (problem != null)
        {
            throw new InvalidOperationException(problem + " TenantSchemaMode.SearchPath needs one physical connection per open, reset between uses, with no default search path.");
        }
    }

    internal static string? AnalyzeConnectionString(string connectionString)
    {
        DbConnectionStringBuilder builder;
        try
        {
            builder = new DbConnectionStringBuilder { ConnectionString = connectionString };
        }
        catch (ArgumentException)
        {
            return "The connection string cannot be parsed.";
        }

        foreach (string key in builder.Keys)
        {
            var name = key.Replace(" ", string.Empty, StringComparison.Ordinal).ToLowerInvariant();
            var value = Convert.ToString(builder[key], System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;

            switch (name)
            {
                case "multiplexing" when IsTrue(value):
                    return "The connection string enables Multiplexing.";
                case "noresetonclose" when IsTrue(value):
                    return "The connection string enables No Reset On Close.";
                case "searchpath" when !string.IsNullOrWhiteSpace(value):
                    return "The connection string sets Search Path.";
                case "options" when value.Replace("\\", string.Empty, StringComparison.Ordinal)
                                         .Replace('-', '_')
                                         .Contains("search_path", StringComparison.OrdinalIgnoreCase):
                    return "The connection string's Options set search_path.";
            }
        }

        return null;
    }

    private static bool IsTrue(string value) =>
        value.Trim() is var v && (v.Equals("true", StringComparison.OrdinalIgnoreCase) || v.Equals("yes", StringComparison.OrdinalIgnoreCase) || v == "1");

    private static string PrepareBind(DbConnection connection, DbContext? context)
    {
        EnsureSupportedConnection(connection);
        var schema = SchemaFor(context);
        if (Transaction.Current != null)
        {
            throw new InvalidOperationException(
                "Refusing to bind search_path inside an ambient transaction (TransactionScope): a rollback would " +
                "restore the default search_path. Open the connection before entering the TransactionScope.");
        }

        return schema;
    }

    private static DbCommand CreateSetCommand(DbConnection connection, string schema)
    {
        var command = connection.CreateCommand();
        command.CommandText = "SELECT set_config('search_path', @pinotechrd_schema, false)";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "pinotechrd_schema";
        parameter.DbType = DbType.String;
        parameter.Value = schema;
        command.Parameters.Add(parameter);
        return command;
    }

    /// <summary>
    /// Reads the bound path and <c>standard_conforming_strings</c> in the same round trip. The session-change scanner
    /// lexes strings as PostgreSQL does with <c>standard_conforming_strings</c> on (its default); with it off, backslashes
    /// in plain strings would make the scanner and the server split a command differently, so binding is refused.
    /// </summary>
    private static DbCommand CreateVerifyCommand(DbConnection connection)
    {
        var command = connection.CreateCommand();
        command.CommandText = "SELECT current_setting('search_path'), current_setting('standard_conforming_strings')";
        return command;
    }

    private static (string? Path, string? ConformingStrings) ReadVerify(DbDataReader reader) =>
        reader.Read()
            ? (reader.IsDBNull(0) ? null : reader.GetString(0), reader.FieldCount > 1 && !reader.IsDBNull(1) ? reader.GetString(1) : null)
            : (null, null);

    private static void Record(DbConnection connection, string schema, (string? Path, string? ConformingStrings) actual)
    {
        if (!string.Equals(actual.Path, schema, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("search_path could not be bound to the tenant schema.");
        }

        // PostgreSQL always answers "on" or "off"; only a non-PostgreSQL stand-in answers NULL.
        if (actual.ConformingStrings != null && !string.Equals(actual.ConformingStrings, "on", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "standard_conforming_strings is off for this session (for example through ALTER DATABASE or ALTER ROLE ... SET). " +
                "TenantSchemaMode.SearchPath requires it on, because the session-change check reads SQL text the way PostgreSQL does with it on.");
        }

        var state = StateFor(connection);
        state.ProcessId = ProcessIdOf(connection);
        state.Schema = schema;
    }
}

/// <summary>
/// Binds each connection EF Core opens to the resolved tenant's schema. See <see cref="SearchPathBinder"/>.
/// </summary>
internal sealed class SearchPathConnectionInterceptor : DbConnectionInterceptor
{
    public static readonly SearchPathConnectionInterceptor Instance = new();

    public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
        => SearchPathBinder.Bind(connection, eventData.Context);

    public override Task ConnectionOpenedAsync(DbConnection connection, ConnectionEndEventData eventData, CancellationToken cancellationToken = default)
        => SearchPathBinder.BindAsync(connection, eventData.Context, cancellationToken);

    public override void ConnectionClosed(DbConnection connection, ConnectionEndEventData eventData)
        => SearchPathBinder.Forget(connection);

    public override Task ConnectionClosedAsync(DbConnection connection, ConnectionEndEventData eventData)
    {
        SearchPathBinder.Forget(connection);
        return Task.CompletedTask;
    }
}

/// <summary>
/// Refuses every EF Core command whose connection is not bound to the current tenant's schema.
/// </summary>
internal sealed class SearchPathCommandInterceptor : DbCommandInterceptor
{
    public static readonly SearchPathCommandInterceptor Instance = new();

    public override InterceptionResult<DbDataReader> ReaderExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result)
    {
        SearchPathBinder.EnsureBound(command, eventData.Context);
        return result;
    }

    public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
    {
        SearchPathBinder.EnsureBound(command, eventData.Context);
        return ValueTask.FromResult(result);
    }

    public override InterceptionResult<int> NonQueryExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<int> result)
    {
        SearchPathBinder.EnsureBound(command, eventData.Context);
        return result;
    }

    public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        SearchPathBinder.EnsureBound(command, eventData.Context);
        return ValueTask.FromResult(result);
    }

    public override InterceptionResult<object> ScalarExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<object> result)
    {
        SearchPathBinder.EnsureBound(command, eventData.Context);
        return result;
    }

    public override ValueTask<InterceptionResult<object>> ScalarExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<object> result, CancellationToken cancellationToken = default)
    {
        SearchPathBinder.EnsureBound(command, eventData.Context);
        return ValueTask.FromResult(result);
    }
}
