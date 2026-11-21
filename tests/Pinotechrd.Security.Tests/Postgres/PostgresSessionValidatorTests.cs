using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Postgres;

/// <summary>
/// <see cref="IAccessTokenSessionValidator"/>, the public session check for hosts that resolve the tenant without
/// <c>UseTenantResolution</c>: called in a scope whose tenant is resolved, as such a host would after authentication,
/// it reports a fresh token active and every way a session ends as ended, in both schema modes on a real database.
/// </summary>
[Collection(PostgresCollection.Name)]
public class PostgresSessionValidatorTests(PostgresFixture postgres) : IAsyncLifetime
{
    private static readonly string[] TenantAUsers =
        ["fresh@a.test", "out@a.test", "revoke@a.test", "reset@a.test", "off@a.test", "update@a.test", "gone@a.test", "own@a.test"];

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

    /// <summary>The principal the bearer scheme builds from the token: its claims, issued by the token's issuer.</summary>
    private static ClaimsPrincipal PrincipalOf(string accessToken) =>
        new(new ClaimsIdentity(new JwtSecurityTokenHandler().ReadJwtToken(accessToken).Claims, "Bearer"));

    private static Task<bool> IsActiveAsync(TenantDatabaseApi api, string tenant, ClaimsPrincipal principal, string? checkedTenant = null) =>
        api.InTenantAsync(tenant, sp => sp.GetRequiredService<IAccessTokenSessionValidator>().IsSessionActiveAsync(principal, checkedTenant ?? tenant));

    private static Task<T> InTenantAAsync<T>(TenantDatabaseApi api, Func<UserManager<HostUser>, IPinotechrdSecurityManager<HostUser, HostRole>, string, Task<T>> work, string email) =>
        api.InTenantAsync("a", async sp =>
        {
            var users = sp.GetRequiredService<UserManager<HostUser>>();
            var id = await users.GetUserIdAsync((await users.FindByEmailAsync(email))!);
            return await work(users, sp.GetRequiredService<IPinotechrdSecurityManager<HostUser, HostRole>>(), id);
        });

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task AFreshToken_ShouldBeActive_OnlyInItsOwnTenant(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var principal = PrincipalOf((await api.LoginAsync("fresh@a.test", "a")).Access);

        (await IsActiveAsync(api, "a", principal)).Should().BeTrue();
        (await IsActiveAsync(api, "b", principal)).Should().BeFalse("the token names tenant a");
        (await IsActiveAsync(api, "a", principal, checkedTenant: "b")).Should().BeFalse("the tenant checked must be the token's");
        (await IsActiveAsync(api, "a", principal, checkedTenant: "")).Should().BeFalse();
        (await IsActiveAsync(api, "b", principal, checkedTenant: "a")).Should().BeFalse("the scope reads tenant b's tables, not a's");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ClaimsAddedByTheApplication_ShouldNotChangeTheAnswer(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var principal = PrincipalOf((await api.LoginAsync("fresh@a.test", "a")).Access);
        // A claims transformation that adds its own id and tenant claims to the bearer identity.
        ((ClaimsIdentity)principal.Identity!).AddClaims([new Claim("id", "other"), new Claim("tenant_id", "b")]);

        (await IsActiveAsync(api, "a", principal)).Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task AnEndedTokenNextToALiveOne_ShouldNotBeActive(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var (ended, _) = await api.LoginAsync("revoke@a.test", "a");
        (await InTenantAAsync(api, (_, manager, id) => manager.RevokeUserSessionsAsync(id), "revoke@a.test")).Should().BeTrue();
        var live = PrincipalOf((await api.LoginAsync("fresh@a.test", "a")).Access);

        live.AddIdentity(PrincipalOf(ended).Identities.Single());

        (await IsActiveAsync(api, "a", live)).Should().BeFalse();
    }

    [Fact]
    public async Task ANullPrincipal_ShouldThrow()
    {
        var api = _hosts[TenantSchemaMode.SearchPath];

        var act = () => IsActiveAsync(api, "a", null!);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task SignOut_ShouldEndTheSession(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var (access, _) = await api.LoginAsync("out@a.test", "a");
        (await IsActiveAsync(api, "a", PrincipalOf(access))).Should().BeTrue();

        (await api.PostAsync("/api/auth/logout", new { }, "a", access)).EnsureSuccessStatusCode();

        (await IsActiveAsync(api, "a", PrincipalOf(access))).Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task RevokeUserSessions_ShouldEndTheSession_AndANewSignInShouldBeActive(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var (access, _) = await api.LoginAsync("revoke@a.test", "a");

        (await InTenantAAsync(api, (_, manager, id) => manager.RevokeUserSessionsAsync(id), "revoke@a.test")).Should().BeTrue();

        (await IsActiveAsync(api, "a", PrincipalOf(access))).Should().BeFalse();
        (await IsActiveAsync(api, "a", PrincipalOf((await api.LoginAsync("revoke@a.test", "a")).Access))).Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task APasswordReset_ShouldEndTheSession(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var (access, _) = await api.LoginAsync("reset@a.test", "a");

        (await InTenantAAsync(api, (_, manager, id) => manager.ResetUserPasswordAsync(id, "N3w-Passw0rd!x"), "reset@a.test")).Should().BeTrue();

        (await IsActiveAsync(api, "a", PrincipalOf(access))).Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task APasswordChange_ShouldEndTheSession(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var (access, _) = await api.LoginAsync("own@a.test", "a");

        (await InTenantAAsync(api, async (users, _, _) =>
            (await users.ChangePasswordAsync((await users.FindByEmailAsync("own@a.test"))!, TenantDatabaseApi.Password, "N3w-Passw0rd!x")).Succeeded,
            "own@a.test")).Should().BeTrue();

        (await IsActiveAsync(api, "a", PrincipalOf(access))).Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task Deactivation_ShouldEndTheSession(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var (access, _) = await api.LoginAsync("off@a.test", "a");

        (await InTenantAAsync(api, (_, manager, id) => manager.SetUserActiveStatusAsync(id, false), "off@a.test")).Should().BeTrue();

        (await IsActiveAsync(api, "a", PrincipalOf(access))).Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task DeactivationThroughUpdateUser_ShouldEndTheSession(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var (access, _) = await api.LoginAsync("update@a.test", "a");

        (await InTenantAAsync(api, async (users, manager, _) =>
        {
            var user = (await users.FindByEmailAsync("update@a.test"))!;
            user.IsActive = false;
            return await manager.UpdateUserAsync(user);
        }, "update@a.test")).Should().BeTrue();

        (await IsActiveAsync(api, "a", PrincipalOf(access))).Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ADeletedUser_ShouldHaveNoSession(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var (access, _) = await api.LoginAsync("gone@a.test", "a");

        (await InTenantAAsync(api, (_, manager, id) => manager.DeleteUserAsync(id), "gone@a.test")).Should().BeTrue();

        (await IsActiveAsync(api, "a", PrincipalOf(access))).Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task APrincipalWithoutALibraryToken_ShouldNotBeActive(TenantSchemaMode mode)
    {
        var api = _hosts[mode];

        (await IsActiveAsync(api, "a", new ClaimsPrincipal(new ClaimsIdentity()))).Should().BeFalse("nothing is authenticated");
        (await IsActiveAsync(api, "a", new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("id", "x"), new Claim("tenant_id", "a")], "Cookies")))).Should().BeFalse("no claim was issued by the library's issuer");
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ATokenWithoutTheSession_ShouldNotBeActive(TenantSchemaMode mode)
    {
        // A token signed with the real key but built by the host (or issued before the library carried the session):
        // the user and tenant are right, but nothing binds it to a session.
        var api = _hosts[mode];
        var (own, _) = await api.LoginAsync("fresh@a.test", "a");
        var claims = new JwtSecurityTokenHandler().ReadJwtToken(own).Claims
            .Where(c => c.Type is "id" or "tenant_id")
            .Select(c => new Claim(c.Type, c.Value));
        var built = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            TenantDatabaseApi.Issuer,
            TenantDatabaseApi.Audience,
            claims,
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(TenantDatabaseApi.Secret)), SecurityAlgorithms.HmacSha256)));

        (await IsActiveAsync(api, "a", PrincipalOf(built))).Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ATokenOfTenantB_ShouldNotBeActiveInTenantA(TenantSchemaMode mode)
    {
        var api = _hosts[mode];
        var bob = PrincipalOf((await api.LoginAsync("bob@b.test", "b")).Access);

        (await IsActiveAsync(api, "b", bob)).Should().BeTrue();
        (await IsActiveAsync(api, "a", bob, checkedTenant: "a")).Should().BeFalse();
    }
}
