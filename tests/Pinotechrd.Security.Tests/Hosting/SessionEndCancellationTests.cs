using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Interfaces;
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
    [InlineData("SignOut")]
    public async Task TheStampRenewalOrDeletion_ShouldFinish_AfterADisconnect(string action)
    {
        await using var api = await TenantDatabaseApi.StartAsync(
            new Dictionary<string, string[]> { ["a"] = ["user@a.test"] },
            configureBuilder: DisconnectDuringSessionEnd.Configure);

        await DisconnectDuringSessionEnd.ShouldFinishAsync(api, "user@a.test", action);
    }

    [Fact]
    public async Task AManagerThatOverridesDelete_ShouldStillBeCalled_NotBypassed()
    {
        await using var api = await TenantDatabaseApi.StartAsync(
            new Dictionary<string, string[]> { ["a"] = ["soft@a.test"] },
            configureBuilder: b => b.Services.AddScoped<UserManager<HostUser>, DisconnectDuringSessionEnd.SoftDeletingUserManager>());

        var deleted = await api.InTenantAsync("a", async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            var id = await users.GetUserIdAsync((await users.FindByEmailAsync("soft@a.test"))!);
            return await sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>().DeleteUserAsync(id);
        });

        deleted.Should().BeTrue();
        var stored = await api.InTenantAsync("a", async sp => await sp.GetRequiredService<UserManager<HostUser>>().FindByEmailAsync("soft@a.test"));
        stored.Should().NotBeNull("the manager's soft delete ran instead of a hard delete");
        stored!.IsActive.Should().BeFalse();
    }

    [Fact]
    public void NewSecurityStamp_ShouldLookLikeIdentitys_ThirtyTwoBase32Characters()
    {
        var stamps = Enumerable.Range(0, 200).Select(_ => UncancellableUserWrites.NewSecurityStamp()).ToArray();

        stamps.Should().OnlyContain(s => s.Length == 32 && s.All(c => (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')));
        stamps.Should().OnlyHaveUniqueItems();
    }
}
