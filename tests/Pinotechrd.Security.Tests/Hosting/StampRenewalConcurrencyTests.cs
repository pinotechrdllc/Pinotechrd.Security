using Xunit;

namespace Pinotechrd.Security.Tests.Hosting;

/// <summary>The session-ending stamp renewal survives a concurrent update of the user (SQLite).</summary>
public class StampRenewalConcurrencyTests
{
    [Fact]
    public async Task RevokeUserSessions_ShouldRenewTheStamp_AfterAConcurrentUpdateOfTheUser()
    {
        await using var api = await TenantDatabaseApi.StartAsync(new Dictionary<string, string[]> { ["a"] = ["user@a.test"] });

        await StampRenewalConcurrency.RevokeShouldRenewTheStampAsync(api, "user@a.test");
    }
}
