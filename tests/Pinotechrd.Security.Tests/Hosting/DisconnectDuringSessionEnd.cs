using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Tests.Hosting;

/// <summary>
/// A client disconnecting right after the refresh tokens are revoked: in ASP.NET Core the user manager's token is the
/// request's <c>RequestAborted</c>, which is then cancelled. The stamp renewal and the deletion that end the session
/// must still happen. Shared by the SQLite and PostgreSQL tests.
/// </summary>
internal static class DisconnectDuringSessionEnd
{
    /// <summary>Stands for <c>RequestAborted</c>: cancelled when the revocation finishes, reset by the test.</summary>
    public sealed class Disconnect
    {
        private CancellationTokenSource _source = new();

        public CancellationToken Token => _source.Token;

        public bool Armed { get; set; }

        public void Fire()
        {
            if (Armed) _source.Cancel();
        }

        public void Reset()
        {
            Armed = false;
            _source = new CancellationTokenSource();
        }
    }

    /// <summary>A user manager whose token is the request's, as <c>AspNetUserManager</c>'s is.</summary>
    public sealed class RequestBoundUserManager(
        IUserStore<HostUser> store,
        IOptions<IdentityOptions> options,
        IPasswordHasher<HostUser> hasher,
        IEnumerable<IUserValidator<HostUser>> userValidators,
        IEnumerable<IPasswordValidator<HostUser>> passwordValidators,
        ILookupNormalizer normalizer,
        IdentityErrorDescriber errors,
        IServiceProvider services,
        ILogger<UserManager<HostUser>> logger,
        Disconnect disconnect)
        : UserManager<HostUser>(store, options, hasher, userValidators, passwordValidators, normalizer, errors, services, logger)
    {
        protected override CancellationToken CancellationToken => disconnect.Token;
    }

    /// <summary>The in-memory store, with the client disconnecting as soon as a user's tokens are revoked.</summary>
    public sealed class DisconnectingStore(Disconnect disconnect) : IRefreshTokenStore
    {
        private readonly InMemoryRefreshTokenStore _inner = new();

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
            disconnect.Fire();
        }
    }

    public static void Configure(WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<Disconnect>();
        builder.Services.AddSingleton<IRefreshTokenStore, DisconnectingStore>();
        builder.Services.AddScoped<UserManager<HostUser>, RequestBoundUserManager>();
    }

    private static Task<string?> StampAsync(TenantDatabaseApi api, string email) =>
        api.InTenantAsync("a", async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            var user = await users.FindByEmailAsync(email);
            return user == null ? null : await users.GetSecurityStampAsync(user);
        });

    /// <summary>Ends a session with the client disconnecting after the revocation, and checks the stamp or the delete.</summary>
    public static async Task ShouldFinishAsync(TenantDatabaseApi api, string email, string action)
    {
        var disconnect = api.Host.Services.GetRequiredService<Disconnect>();
        var before = await StampAsync(api, email);
        before.Should().NotBeNull();

        var ended = await api.InTenantAsync("a", async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            var id = await users.GetUserIdAsync((await users.FindByEmailAsync(email))!);
            var manager = sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>();
            disconnect.Armed = true;
            return action switch
            {
                "Revoke" => await manager.RevokeUserSessionsAsync(id),
                "Deactivate" => await manager.SetUserActiveStatusAsync(id, false),
                _ => await manager.DeleteUserAsync(id),
            };
        });
        disconnect.Token.IsCancellationRequested.Should().BeTrue("the client disconnected after the revocation");
        disconnect.Reset();

        ended.Should().BeTrue();
        var after = await StampAsync(api, email);
        if (action == "Delete") after.Should().BeNull("the user is deleted");
        else after.Should().NotBe(before, "the stamp is renewed although the request was cancelled");
    }
}
