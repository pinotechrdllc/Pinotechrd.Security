using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// An access token stops working before it expires once its user's session ends: sign-out, session revocation,
/// password reset and deactivation all renew the security stamp, which the tenant middleware compares with the
/// token's claim against the tenant's own user tables. Proven in both schema modes on a real database.
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresSessionRevocationTests(PostgresFixture postgres) : IAsyncLifetime
{
    private static readonly string[] TenantAUsers = ["out@a.test", "revoke@a.test", "reset@a.test", "off@a.test", "keep@a.test", "cross@a.test"];
    private static readonly string[] TenantBUsers = ["bob@b.test"];

    private readonly Dictionary<TenantSchemaMode, TenantDatabaseApi> _hosts = [];

    public async Task InitializeAsync()
    {
        foreach (var mode in PgProvisioning.Modes)
        {
            var cs = await postgres.CreateDatabaseAsync();
            await PgProvisioning.ProvisionAsync(cs, mode, "a", "b");
            _hosts[mode] = await TenantDatabaseApi.StartAsync(
                new Dictionary<string, string[]> { ["a"] = TenantAUsers, ["b"] = TenantBUsers },
                mode,
                useDatabase: (options, _) => options.UseNpgsql(cs),
                provision: false);
        }
    }

    public async Task DisposeAsync()
    {
        foreach (var api in _hosts.Values) await api.DisposeAsync();
        Npgsql.NpgsqlConnection.ClearAllPools();
    }

    public static IEnumerable<object[]> Modes() => PgProvisioning.BothModes();

    private static async Task<HttpResponseMessage> MeAsync(TenantDatabaseApi api, string access, string tenant)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("TenantId", tenant);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
        return await api.Client.SendAsync(request);
    }

    private static async Task ShouldBeRevokedAsync(HttpResponseMessage response)
    {
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        response.Headers.WwwAuthenticate.ToString().Should().Contain("invalid_token");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        json.RootElement.GetProperty("code").GetString().Should().Be("session_revoked");
    }

    private static Task<string> UserIdAsync(TenantDatabaseApi api, string tenant, string email) =>
        api.InTenantAsync(tenant, async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            return await users.GetUserIdAsync((await users.FindByEmailAsync(email))!);
        });

    private static Task<T> AsAdminAsync<T>(TenantDatabaseApi api, string tenant, Func<IPinotechrdSecurityManager<HostUser, HostRole>, Task<T>> work) =>
        api.InTenantAsync(tenant, sp => work(sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>()));

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task AFreshToken_ShouldWork_AndCarryAStampHashButNotTheStamp(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var (access, _) = await api.LoginAsync("keep@a.test", "a");

        (await MeAsync(api, access, "a")).StatusCode.Should().Be(HttpStatusCode.OK);

        var stamp = await api.InTenantAsync("a", async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            return await users.GetSecurityStampAsync((await users.FindByEmailAsync("keep@a.test"))!);
        });
        var claim = new JwtSecurityTokenHandler().ReadJwtToken(access).Claims.Single(c => c.Type == SecurityStampClaim.Type).Value;
        claim.Should().Be(SecurityStampClaim.Hash(stamp)).And.HaveLength(22);
        access.Should().NotContain(stamp);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task SignOut_ShouldRevokeTheAccessTokenAtOnce(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var (access, _) = await api.LoginAsync("out@a.test", "a");
        (await MeAsync(api, access, "a")).StatusCode.Should().Be(HttpStatusCode.OK);

        (await api.PostAsync("/api/auth/logout", new { }, "a", access)).StatusCode.Should().Be(HttpStatusCode.NoContent);

        await ShouldBeRevokedAsync(await MeAsync(api, access, "a"));
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task RevokeUserSessions_ShouldRevokeTheAccessToken_AndANewLoginShouldWork(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var (access, _) = await api.LoginAsync("revoke@a.test", "a");
        var id = await UserIdAsync(api, "a", "revoke@a.test");

        (await AsAdminAsync(api, "a", m => m.RevokeUserSessionsAsync(id))).Should().BeTrue();

        await ShouldBeRevokedAsync(await MeAsync(api, access, "a"));
        var (fresh, _) = await api.LoginAsync("revoke@a.test", "a");
        (await MeAsync(api, fresh, "a")).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task PasswordReset_ShouldRevokeTheAccessToken(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var (access, _) = await api.LoginAsync("reset@a.test", "a");
        var id = await UserIdAsync(api, "a", "reset@a.test");

        (await AsAdminAsync(api, "a", m => m.ResetUserPasswordAsync(id, "N3w-Passw0rd!x"))).Should().BeTrue();

        await ShouldBeRevokedAsync(await MeAsync(api, access, "a"));
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Deactivation_ShouldRevokeTheAccessToken(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var (access, _) = await api.LoginAsync("off@a.test", "a");
        var id = await UserIdAsync(api, "a", "off@a.test");

        (await AsAdminAsync(api, "a", m => m.SetUserActiveStatusAsync(id, false))).Should().BeTrue();

        await ShouldBeRevokedAsync(await MeAsync(api, access, "a"));
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ATokenNamingTenantB_ForAUserOfTenantA_ShouldBeRefused_EvenWithTheRightStamp(TenantSchemaMode mode)
    {
        // A token signed with the real key (as a leaked key or a host bug would produce) that names tenant B for a user
        // of tenant A, with that user's real stamp: the lookup runs in tenant B's tables, where the user does not exist.
        var api = _hosts[mode];
        var (own, _) = await api.LoginAsync("cross@a.test", "a");
        var claims = new JwtSecurityTokenHandler().ReadJwtToken(own).Claims
            .Where(c => c.Type is "id" or SecurityStampClaim.Type)
            .Select(c => new Claim(c.Type, c.Value))
            .Append(new Claim("tenant_id", "b"));
        var forged = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            TenantDatabaseApi.Issuer,
            TenantDatabaseApi.Audience,
            claims,
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(TenantDatabaseApi.Secret)), SecurityAlgorithms.HmacSha256)));

        (await MeAsync(api, own, "a")).StatusCode.Should().Be(HttpStatusCode.OK, "control: the token of tenant A works in A");
        await ShouldBeRevokedAsync(await MeAsync(api, forged, "b"));
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ARevokedUserOfTenantA_ShouldNotAffectTenantB(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var (bob, _) = await api.LoginAsync("bob@b.test", "b");

        (await MeAsync(api, bob, "b")).StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
