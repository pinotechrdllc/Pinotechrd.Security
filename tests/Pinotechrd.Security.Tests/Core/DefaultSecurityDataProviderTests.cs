using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Options;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>
/// Who the default <c>ISecurityDataProvider</c> says the user and the tenant are. Roles and permissions are proven on
/// PostgreSQL in <c>PostgresReadmeFlowTests</c>; a real bearer handler whose token the application fails is in
/// <c>DefaultSecurityDataProviderHostTests</c>.
/// </summary>
public class DefaultSecurityDataProviderTests
{
    private const string Issuer = "library-issuer";

    private static (DefaultSecurityDataProvider<SecDb, HostUser, HostRole> Provider, DefaultHttpContext Http, TenantContext Tenant) Create()
    {
        var http = new DefaultHttpContext();
        var tenant = new TenantContext();
        var options = Microsoft.Extensions.Options.Options.Create(new PinotechrdSecurityOptions { Jwt = { Issuer = Issuer } });
        var provider = new DefaultSecurityDataProvider<SecDb, HostUser, HostRole>(new HttpContextAccessor { HttpContext = http }, tenant, null!, options);
        return (provider, http, tenant);
    }

    private static ClaimsIdentity Identity(string authenticationType, string issuer, params (string Type, string Value)[] claims) =>
        new(claims.Select(c => new Claim(c.Type, c.Value, ClaimValueTypes.String, issuer)), authenticationType);

    private static ClaimsIdentity LibraryToken(params string[] ids) =>
        Identity("Bearer", Issuer, ids.Select(id => ("id", id)).ToArray());

    [Fact]
    public void TheUser_ShouldBeTheOneOfTheLibrarysValidatedToken()
    {
        var (provider, http, _) = Create();
        var token = LibraryToken("token-user");
        ValidatedAccessToken.Record(http, new ClaimsPrincipal(token));
        http.User = new ClaimsPrincipal(token);

        provider.GetCurrentUserId().Should().Be("token-user");
    }

    [Fact]
    public void AnIdClaimOfAnotherIssuerOrScheme_ShouldNeverNameAUser()
    {
        var (provider, http, _) = Create();

        http.User = new ClaimsPrincipal(Identity("Cookie", "LOCAL AUTHORITY", ("id", "cookie-user")));
        provider.GetCurrentUserId().Should().BeNull("a cookie's id claim is not the library's");

        http.User = new ClaimsPrincipal(Identity("Partner", "https://idp.example", ("id", "partner-user")));
        provider.GetCurrentUserId().Should().BeNull("another JWT issuer's id claim is not the library's");

        var token = LibraryToken("token-user");
        http.User = new ClaimsPrincipal([token, Identity("Cookie", "LOCAL AUTHORITY", ("id", "someone-else"))]);
        provider.GetCurrentUserId().Should().Be("token-user", "the other identity's id is ignored, not counted as a disagreement");
    }

    [Fact]
    public void ARecordedTokenThatIsNotTheAuthenticatedIdentity_ShouldNameNobody()
    {
        // The bearer scheme recorded user A's token, but the identity the request carries is another library-issued user
        // (for example the application failed A's token and another scheme authenticated B with a library token).
        var (provider, http, _) = Create();
        ValidatedAccessToken.Record(http, new ClaimsPrincipal(LibraryToken("user-a")));
        http.User = new ClaimsPrincipal(LibraryToken("user-b"));

        provider.GetCurrentUserId().Should().BeNull();
    }

    [Fact]
    public void ARecordedTokenWithoutAnAuthenticatedIdentity_ShouldNameNobody()
    {
        var (provider, http, _) = Create();
        ValidatedAccessToken.Record(http, new ClaimsPrincipal(LibraryToken("token-user")));
        http.User = new ClaimsPrincipal([Identity("Cookie", "LOCAL AUTHORITY", ("name", "x"))]);

        provider.GetCurrentUserId().Should().BeNull();
    }

    [Fact]
    public void TwoUserIdsOrNoAuthentication_ShouldNameNobody()
    {
        var (provider, http, _) = Create();

        http.User = new ClaimsPrincipal(LibraryToken("a", "b"));
        provider.GetCurrentUserId().Should().BeNull("one token naming two users");

        http.User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("id", "x", ClaimValueTypes.String, Issuer) }));
        provider.GetCurrentUserId().Should().BeNull("an identity that is not authenticated names nobody");
    }

    [Fact]
    public void TheTenant_ShouldBeTheResolvedOne_NeverTheHeader()
    {
        var (provider, http, tenant) = Create();
        http.Request.Headers["TenantId"] = "from-header";

        provider.GetCurrentTenantId().Should().BeNull("nothing was resolved");
        tenant.SetTenant("resolved");
        provider.GetCurrentTenantId().Should().Be("resolved");
    }

    [Fact]
    public void OutsideARequest_ThereShouldBeNoUser()
    {
        var options = Microsoft.Extensions.Options.Options.Create(new PinotechrdSecurityOptions { Jwt = { Issuer = Issuer } });
        var provider = new DefaultSecurityDataProvider<SecDb, HostUser, HostRole>(new HttpContextAccessor(), new TenantContext(), null!, options);

        provider.GetCurrentUserId().Should().BeNull();
    }
}
