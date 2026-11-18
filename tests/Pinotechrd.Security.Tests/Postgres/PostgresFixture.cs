using Npgsql;
using Testcontainers.PostgreSql;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// One PostgreSQL 17.7 container for every PostgreSQL test of the run. The tests of this collection fail, they are never
/// skipped, when Docker is not available: the guarantees they prove (schemas, search_path, concurrency) cannot be shown anywhere else.
/// Each test class asks for its own database, so classes do not see each other's data.
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    public const string Image = "postgres:17.7";

    private PostgreSqlContainer? _container;
    private int _databases;

    public async Task InitializeAsync()
    {
        try
        {
            _container = new PostgreSqlBuilder(Image)
                .WithCommand("-c", "max_connections=400")
                .Build();
            await _container.StartAsync();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"The PostgreSQL tests need a Docker daemon able to run '{Image}' (Testcontainers could not start it). " +
                "These tests fail instead of skipping so that a missing Docker cannot hide a broken tenant-isolation guarantee.", ex);
        }
    }

    public async Task DisposeAsync()
    {
        NpgsqlConnection.ClearAllPools();
        if (_container != null) await _container.DisposeAsync();
    }

    /// <summary>The server's max_connections, to assert that the container really started with the raised limit.</summary>
    public async Task<string> MaxConnectionsAsync()
    {
        await using var connection = new NpgsqlConnection(_container!.GetConnectionString());
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SHOW max_connections";
        return (string)(await command.ExecuteScalarAsync())!;
    }

    /// <summary>Creates an empty database and returns a connection string for it (superuser, as the container's default).</summary>
    public async Task<string> CreateDatabaseAsync(string? options = null)
    {
        var name = "t" + Interlocked.Increment(ref _databases) + "_" + Guid.NewGuid().ToString("N")[..8];
        await using (var admin = new NpgsqlConnection(_container!.GetConnectionString()))
        {
            await admin.OpenAsync();
            await using var command = admin.CreateCommand();
            command.CommandText = $"CREATE DATABASE \"{name}\"";
            await command.ExecuteNonQueryAsync();
        }

        var builder = new NpgsqlConnectionStringBuilder(_container.GetConnectionString()) { Database = name };
        // Small, short-lived pools: every test class has its own database and so its own pools.
        builder.MaxPoolSize = 40;
        builder.MinPoolSize = 0;
        builder.ConnectionIdleLifetime = 2;
        builder.ConnectionPruningInterval = 1;
        var cs = builder.ConnectionString;
        return options == null ? cs : cs + ";" + options;
    }
}

[CollectionDefinition(Name)]
public sealed class PostgresCollection : ICollectionFixture<PostgresFixture>
{
    public const string Name = "postgres";
}
