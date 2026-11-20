using Xunit;

namespace Pinotechrd.Security.Tests.Hosting;

/// <summary>
/// Ending a session finishes when the client disconnects right after the refresh tokens are revoked (SQLite; the
/// PostgreSQL run is in <c>PostgresSessionEndCancellationTests</c>).
/// </summary>
public class SessionEndCancellationTests
{
    [Theory]
    [InlineData("Revoke")]
    [InlineData("Deactivate")]
    [InlineData("Delete")]
    public async Task TheStampRenewalOrDeletion_ShouldFinish_AfterADisconnect(string action)
    {
        await using var api = await TenantDatabaseApi.StartAsync(
            new Dictionary<string, string[]> { ["a"] = ["user@a.test"] },
            configureBuilder: DisconnectDuringSessionEnd.Configure);

        await DisconnectDuringSessionEnd.ShouldFinishAsync(api, "user@a.test", action);
    }
}
