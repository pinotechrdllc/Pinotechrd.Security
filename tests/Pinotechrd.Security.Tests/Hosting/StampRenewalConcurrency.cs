using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Tests.Hosting;

/// <summary>
/// Another request updates the user between the lookup and the stamp renewal of a session end (for example a sign-in
/// resetting the failed count): the renewal must reload the user and try again rather than leave the old stamp valid.
/// Shared by the SQLite and PostgreSQL tests.
/// </summary>
internal static class StampRenewalConcurrency
{
    private static Task<string> StampAsync(TenantDatabaseApi api, string email) =>
        api.InTenantAsync("a", async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            return await users.GetSecurityStampAsync((await users.FindByEmailAsync(email))!);
        });

    public static async Task RevokeShouldRenewTheStampAsync(TenantDatabaseApi api, string email)
    {
        var before = await StampAsync(api, email);

        var revoked = await api.InTenantAsync("a", async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            // Loaded and tracked in this scope, as a request would.
            var user = (await users.FindByEmailAsync(email))!;
            var id = await users.GetUserIdAsync(user);

            // Another request updates the same user, which changes its concurrency stamp.
            (await api.InTenantAsync("a", async other =>
            {
                var otherUsers = other.GetRequiredService<UserManager<HostUser>>();
                var copy = (await otherUsers.FindByIdAsync(id))!;
                copy.PhoneNumber = "555-0199";
                return (await otherUsers.UpdateAsync(copy)).Succeeded;
            })).Should().BeTrue();

            // The lookup inside returns the stale tracked instance.
            return await sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>().RevokeUserSessionsAsync(id);
        });

        revoked.Should().BeTrue("the renewal is retried after the concurrency conflict");
        (await StampAsync(api, email)).Should().NotBe(before);
        (await api.InTenantAsync("a", async sp =>
            (await sp.GetRequiredService<UserManager<HostUser>>().FindByEmailAsync(email))!.PhoneNumber))
            .Should().Be("555-0199", "the other request's change is kept");
    }
}
