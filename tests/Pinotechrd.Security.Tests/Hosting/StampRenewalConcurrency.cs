using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Core;
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

    /// <summary>
    /// The in-memory store, with another request editing the user right after its tokens are revoked: that is after the
    /// deactivation is saved and before the stamp renewal, the window the retry covers.
    /// </summary>
    public sealed class EditingStore(IServiceProvider services) : IRefreshTokenStore
    {
        private readonly InMemoryRefreshTokenStore _inner = new();

        public bool Armed { get; set; }

        public Task SaveAsync(string userId, string tenantId, string refreshToken, DateTime expiresAtUtc, string? familyId = null, string? securityStamp = null, CancellationToken cancellationToken = default)
            => _inner.SaveAsync(userId, tenantId, refreshToken, expiresAtUtc, familyId, securityStamp, cancellationToken);

        public Task<RefreshTokenValidationResult> ValidateAsync(string refreshToken, CancellationToken cancellationToken = default)
            => _inner.ValidateAsync(refreshToken, cancellationToken);

        public Task<RefreshTokenConsumeResult> ConsumeAsync(string refreshToken, string expectedTenantId, CancellationToken cancellationToken = default)
            => _inner.ConsumeAsync(refreshToken, expectedTenantId, cancellationToken);

        public Task RevokeAsync(string refreshToken, CancellationToken cancellationToken = default)
            => _inner.RevokeAsync(refreshToken, cancellationToken);

        public async Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default)
        {
            await _inner.RevokeAllForUserAsync(userId, cancellationToken);
            if (!Armed) return;
            Armed = false;
            using var scope = services.CreateScope();
            scope.ServiceProvider.GetRequiredService<Pinotechrd.Security.Tenancy.TenantContext>().SetTenant("a");
            var users = scope.ServiceProvider.GetRequiredService<UserManager<HostUser>>();
            var copy = (await users.FindByIdAsync(userId))!;
            copy.PhoneNumber = "555-0123";
            (await users.UpdateAsync(copy)).Succeeded.Should().BeTrue();
        }
    }

    public static void Configure(WebApplicationBuilder builder) =>
        builder.Services.AddSingleton<IRefreshTokenStore, EditingStore>();

    /// <summary>Ends the sessions by <paramref name="action"/> with a concurrent edit before the stamp renewal.</summary>
    public static async Task EndingShouldRenewTheStampAsync(TenantDatabaseApi api, string email, string action)
    {
        var before = await StampAsync(api, email);
        var store = (EditingStore)api.Host.Services.GetRequiredService<IRefreshTokenStore>();

        var ended = await api.InTenantAsync("a", async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            var manager = sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>();
            var user = (await users.FindByEmailAsync(email))!;
            var id = await users.GetUserIdAsync(user);
            store.Armed = true;
            if (action == "Deactivate") return await manager.SetUserActiveStatusAsync(id, false);
            user.IsActive = false;
            return await manager.UpdateUserAsync(user);
        });

        store.Armed.Should().BeFalse("the concurrent edit ran");
        ended.Should().BeTrue("the renewal is retried after the concurrency conflict");
        (await StampAsync(api, email)).Should().NotBe(before);
        var stored = await api.InTenantAsync("a", async sp => (await sp.GetRequiredService<UserManager<HostUser>>().FindByEmailAsync(email))!);
        stored.PhoneNumber.Should().Be("555-0123", "the other request's change is kept");
        stored.IsActive.Should().BeFalse();
    }
}
