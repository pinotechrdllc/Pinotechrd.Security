using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;
using Xunit;

namespace Pinotechrd.Security.Tests.Hosting;

/// <summary>
/// The security-stamp check on access tokens (<see cref="JwtSettings.ValidateSecurityStamp"/>) through the real
/// pipeline: its switch, its cache interval and tokens that lack the claim. PostgreSQL coverage of the revocation
/// paths is in <c>PostgresSessionRevocationTests</c>.
/// </summary>
public class SessionRevocationTests
{
    private const string User = "user@a.test";

    private static Task<TenantDatabaseApi> StartAsync(
        Action<PinotechrdSecurityOptions>? configure = null, Action<WebApplicationBuilder>? builder = null) =>
        TenantDatabaseApi.StartAsync(new Dictionary<string, string[]> { ["a"] = [User] }, configureBuilder: builder, configureSecurity: configure);

    private static async Task<HttpStatusCode> MeAsync(TenantDatabaseApi api, string access)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("TenantId", "a");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
        return (await api.Client.SendAsync(request)).StatusCode;
    }

    private static async Task LogoutAsync(TenantDatabaseApi api, string access) =>
        (await api.PostAsync("/api/auth/logout", new { }, "a", access)).StatusCode.Should().Be(HttpStatusCode.NoContent);

    private static string Resign(string access, Func<IEnumerable<Claim>, IEnumerable<Claim>> change) =>
        new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            TenantDatabaseApi.Issuer,
            TenantDatabaseApi.Audience,
            change(new JwtSecurityTokenHandler().ReadJwtToken(access).Claims
                .Where(c => c.Type is not ("iss" or "aud" or "exp" or "nbf" or "iat"))
                .Select(c => new Claim(c.Type, c.Value))),
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(TenantDatabaseApi.Secret)), SecurityAlgorithms.HmacSha256)));

    [Fact]
    public async Task ByDefault_SignOut_ShouldRevokeTheAccessTokenAtOnce()
    {
        await using var api = await StartAsync();
        var (access, _) = await api.LoginAsync(User, "a");
        (await MeAsync(api, access)).Should().Be(HttpStatusCode.OK);

        await LogoutAsync(api, access);

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("TenantId", "a");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
        var response = await api.Client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        response.Headers.WwwAuthenticate.ToString().Should().Be("Bearer error=\"invalid_token\"");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        json.RootElement.GetProperty("code").GetString().Should().Be("session_revoked");
    }

    private sealed class RebuildingTransformation : IClaimsTransformation
    {
        // Re-creates every claim, as hosts do to map claims; the copies lose the token's issuer.
        public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal) =>
            Task.FromResult(new ClaimsPrincipal(principal.Identities.Select(i =>
                new ClaimsIdentity(i.Claims.Select(c => new Claim(c.Type, c.Value)), i.AuthenticationType))));
    }

    [Fact]
    public async Task AClaimsTransformationThatRebuildsTheClaims_ShouldNotHideTheToken()
    {
        await using var api = await StartAsync(builder: b => b.Services.AddTransient<IClaimsTransformation, RebuildingTransformation>());
        var (access, _) = await api.LoginAsync(User, "a");
        (await MeAsync(api, access)).Should().Be(HttpStatusCode.OK);

        await LogoutAsync(api, access);

        (await MeAsync(api, access)).Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task SignIn_ShouldWork_WhileTheClientStillSendsItsEndedToken()
    {
        await using var api = await StartAsync();
        var (access, _) = await api.LoginAsync(User, "a");
        await LogoutAsync(api, access);

        var login = await api.PostAsync("/api/auth/login", new LoginRequest(User, TenantDatabaseApi.Password), "a", access);

        login.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    private sealed class ClaimAddingValidator : IIdentityValidator<HostUser>
    {
        public Task<IdentityValidationResult> ValidateAsync(HostUser user, string tenantId, CancellationToken cancellationToken = default) =>
            Task.FromResult(IdentityValidationResult.Success(
                "Name", [new Claim("id", "employee-7"), new Claim(SecurityStampClaim.Type, "forged"), new Claim("employee", "7")]));
    }

    [Fact]
    public async Task AValidatorCannotSupplyTheUserIdOrStampClaims()
    {
        await using var api = await StartAsync(builder: b => b.Services.AddScoped<IIdentityValidator<HostUser>, ClaimAddingValidator>());
        var (access, _) = await api.LoginAsync(User, "a");

        var claims = new JwtSecurityTokenHandler().ReadJwtToken(access).Claims.ToList();
        claims.Where(c => c.Type == "id").Should().ContainSingle().Which.Value.Should().NotBe("employee-7");
        claims.Where(c => c.Type == SecurityStampClaim.Type).Should().ContainSingle().Which.Value.Should().NotBe("forged");
        claims.Should().Contain(c => c.Type == "employee" && c.Value == "7");
        (await MeAsync(api, access)).Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task WhenTurnedOff_ATokenShouldWorkUntilItExpires_AsBefore()
    {
        await using var api = await StartAsync(o => o.Jwt.ValidateSecurityStamp = false);
        var (access, _) = await api.LoginAsync(User, "a");

        await LogoutAsync(api, access);

        (await MeAsync(api, access)).Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task WithAnInterval_TheCachedAnswerShouldBeReused_UntilItExpires()
    {
        // The documented window: within the interval a revocation is not seen yet.
        await using var api = await StartAsync(o => o.Jwt.SecurityStampValidationInterval = TimeSpan.FromMinutes(5));
        var (access, _) = await api.LoginAsync(User, "a");
        (await MeAsync(api, access)).Should().Be(HttpStatusCode.OK);

        await LogoutAsync(api, access);

        (await MeAsync(api, access)).Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ATokenWithoutTheStampClaim_ShouldBeRefused()
    {
        await using var api = await StartAsync();
        var (access, _) = await api.LoginAsync(User, "a");

        var withoutStamp = Resign(access, claims => claims.Where(c => c.Type != SecurityStampClaim.Type));

        (await MeAsync(api, Resign(access, claims => claims))).Should().Be(HttpStatusCode.OK, "control: re-signing alone keeps the token valid");
        (await MeAsync(api, withoutStamp)).Should().Be(HttpStatusCode.Unauthorized);
    }

    [Theory]
    [InlineData("other")]
    [InlineData("")]
    public async Task ATokenWithAnotherStampHash_ShouldBeRefused(string stamp)
    {
        await using var api = await StartAsync();
        var (access, _) = await api.LoginAsync(User, "a");

        var wrong = Resign(access, claims => claims.Where(c => c.Type != SecurityStampClaim.Type).Append(new Claim(SecurityStampClaim.Type, stamp)));

        (await MeAsync(api, wrong)).Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task ATokenWithTwoStampClaims_ShouldBeRefused()
    {
        await using var api = await StartAsync();
        var (access, _) = await api.LoginAsync(User, "a");
        var hash = new JwtSecurityTokenHandler().ReadJwtToken(access).Claims.Single(c => c.Type == SecurityStampClaim.Type).Value;

        var doubled = Resign(access, claims => claims.Append(new Claim(SecurityStampClaim.Type, hash)));

        (await MeAsync(api, doubled)).Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task ATokenForAnUnknownUserId_ShouldBeRefused()
    {
        await using var api = await StartAsync();
        var (access, _) = await api.LoginAsync(User, "a");

        var unknown = Resign(access, claims => claims.Where(c => c.Type != "id").Append(new Claim("id", Guid.NewGuid().ToString())));
        var unparsable = Resign(access, claims => claims.Where(c => c.Type != "id").Append(new Claim("id", "not-a-guid")));

        (await MeAsync(api, unknown)).Should().Be(HttpStatusCode.Unauthorized);
        (await MeAsync(api, unparsable)).Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public void Hash_ShouldBeEmptyForNoStamp_And22UrlSafeCharactersOtherwise()
    {
        SecurityStampClaim.Hash(null).Should().BeEmpty();
        SecurityStampClaim.Hash("").Should().BeEmpty();
        SecurityStampClaim.Hash("ABC").Should().HaveLength(22).And.MatchRegex("^[A-Za-z0-9_-]+$")
            .And.NotBe(SecurityStampClaim.Hash("ABD"));
    }
}
