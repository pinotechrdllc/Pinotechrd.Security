using System.Net;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// Wrong passwords sent in parallel all count toward the Identity lockout: each update that loses the concurrency
/// stamp to another is retried, so N failures leave the count at N, or the account locked out.
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresParallelFailedSignInTests(PostgresFixture postgres)
{
    private const int Attempts = 30;

    public static IEnumerable<object[]> Modes() => PgProvisioning.BothModes();

    private async Task<TenantDatabaseApi> StartAsync(TenantSchemaMode mode, int maxFailedAccessAttempts)
    {
        var cs = await postgres.CreateDatabaseAsync();
        await PgProvisioning.ProvisionAsync(cs, mode, "a");
        return await TenantDatabaseApi.StartAsync(
            new Dictionary<string, string[]> { ["a"] = ["user@a.test"] },
            mode,
            useDatabase: (options, _) => options.UseNpgsql(cs),
            provision: false,
            configureBuilder: builder => builder.Services.Configure<IdentityOptions>(o => o.Lockout.MaxFailedAccessAttempts = maxFailedAccessAttempts));
    }

    private static async Task<HttpStatusCode[]> WrongPasswordsInParallelAsync(TenantDatabaseApi api) =>
        await Task.WhenAll(Enumerable.Range(0, Attempts).Select(_ => Task.Run(async () =>
            (await api.PostAsync("/api/auth/login", new LoginRequest("user@a.test", "Wr0ng-Passw0rd!"), "a")).StatusCode)));

    private static Task<(int Count, bool LockedOut)> StateAsync(TenantDatabaseApi api) =>
        api.InTenantAsync("a", async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            var user = (await users.FindByEmailAsync("user@a.test"))!;
            return (await users.GetAccessFailedCountAsync(user), await users.IsLockedOutAsync(user));
        });

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task EveryParallelFailure_ShouldCount(TenantSchemaMode mode)
    {
        await using var api = await StartAsync(mode, maxFailedAccessAttempts: 1000);

        var statuses = await WrongPasswordsInParallelAsync(api);
        var (count, lockedOut) = await StateAsync(api);

        statuses.Should().OnlyContain(s => s == HttpStatusCode.Unauthorized);
        count.Should().Be(Attempts);
        lockedOut.Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ParallelFailures_ShouldLockTheAccount(TenantSchemaMode mode)
    {
        await using var api = await StartAsync(mode, maxFailedAccessAttempts: 5);

        await WrongPasswordsInParallelAsync(api);
        var (_, lockedOut) = await StateAsync(api);

        lockedOut.Should().BeTrue();
        (await api.PostAsync("/api/auth/login", new LoginRequest("user@a.test", TenantDatabaseApi.Password), "a"))
            .StatusCode.Should().Be(HttpStatusCode.Unauthorized, "the right password is refused while locked out");
    }
}
