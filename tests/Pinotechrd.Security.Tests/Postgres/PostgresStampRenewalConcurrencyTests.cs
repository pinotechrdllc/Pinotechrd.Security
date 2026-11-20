using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>The session-ending stamp renewal survives a concurrent update of the user, in both schema modes.</summary>
[Collection(PostgresCollection.Name)]
public class PostgresStampRenewalConcurrencyTests(PostgresFixture postgres)
{
    public static IEnumerable<object[]> Modes() => PgProvisioning.BothModes();

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task RevokeUserSessions_ShouldRenewTheStamp_AfterAConcurrentUpdateOfTheUser(TenantSchemaMode mode)
    {
        var cs = await postgres.CreateDatabaseAsync();
        await PgProvisioning.ProvisionAsync(cs, mode, "a");
        await using var api = await TenantDatabaseApi.StartAsync(
            new Dictionary<string, string[]> { ["a"] = ["user@a.test"] },
            mode,
            useDatabase: (options, _) => options.UseNpgsql(cs),
            provision: false);

        await StampRenewalConcurrency.RevokeShouldRenewTheStampAsync(api, "user@a.test");
        Npgsql.NpgsqlConnection.ClearAllPools();
    }

    public static IEnumerable<object[]> ModesAndActions() =>
        PgProvisioning.Modes.SelectMany(mode => new[] { "Deactivate", "UpdateUser" }.Select(action => new object[] { mode, action }));

    [Theory]
    [MemberData(nameof(ModesAndActions))]
    public async Task Deactivation_ShouldRenewTheStamp_WhenAnotherRequestEditsTheUserBeforeTheRenewal(TenantSchemaMode mode, string action)
    {
        var cs = await postgres.CreateDatabaseAsync();
        await PgProvisioning.ProvisionAsync(cs, mode, "a");
        await using var api = await TenantDatabaseApi.StartAsync(
            new Dictionary<string, string[]> { ["a"] = ["user@a.test"] },
            mode,
            useDatabase: (options, _) => options.UseNpgsql(cs),
            provision: false,
            configureBuilder: StampRenewalConcurrency.Configure);

        await StampRenewalConcurrency.EndingShouldRenewTheStampAsync(api, "user@a.test", action);
        Npgsql.NpgsqlConnection.ClearAllPools();
    }
}
