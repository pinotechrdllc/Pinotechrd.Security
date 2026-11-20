using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// Ending a session finishes on PostgreSQL, in both schema modes, when the client disconnects right after the refresh
/// tokens are revoked: the stamp renewal and the deletion do not use the request's token.
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresSessionEndCancellationTests(PostgresFixture postgres)
{
    public static IEnumerable<object[]> Cases() =>
        PgProvisioning.Modes.SelectMany(mode => new[] { "Revoke", "Deactivate", "Delete", "SignOut" }.Select(action => new object[] { mode, action }));

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task TheStampRenewalOrDeletion_ShouldFinish_AfterADisconnect(TenantSchemaMode mode, string action)
    {
        var cs = await postgres.CreateDatabaseAsync();
        await PgProvisioning.ProvisionAsync(cs, mode, "a");
        await using var api = await TenantDatabaseApi.StartAsync(
            new Dictionary<string, string[]> { ["a"] = ["user@a.test"] },
            mode,
            useDatabase: (options, _) => options.UseNpgsql(cs),
            provision: false,
            configureBuilder: DisconnectDuringSessionEnd.Configure);

        await DisconnectDuringSessionEnd.ShouldFinishAsync(api, "user@a.test", action);
        Npgsql.NpgsqlConnection.ClearAllPools();
    }
}
