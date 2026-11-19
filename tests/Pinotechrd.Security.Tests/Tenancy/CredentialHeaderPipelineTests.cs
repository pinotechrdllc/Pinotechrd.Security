using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Pinotechrd.Security.Authorization;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Tenancy;

/// <summary>
/// The reported hole: the default authentication scheme is a cookie, an endpoint accepts only Bearer tokens, and the
/// tenant middleware (which runs on the default scheme) sees an anonymous request. A header naming another tenant
/// must not become the tenant of a request that carries a bearer token.
/// </summary>
public class CredentialHeaderPipelineTests
{
    private static readonly SymmetricSecurityKey Key = new("credential-pipeline-signing-key-32-bytes!!"u8.ToArray());

    private static string BearerFor(string tenant)
    {
        var token = new JwtSecurityToken(
            claims: [new Claim("tenant_id", tenant), new Claim("sub", "user-1")],
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(Key, SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static Task<InProcessHost> StartCookieDefaultAsync(ISecurityEngine engine) =>
        InProcessHost.StartAsync(
            builder =>
            {
                var services = builder.Services;
                services.AddScoped<TenantContext>();
                services.AddSingleton(new TenantResolutionOptions());
                services.AddSingleton<ITenantStore>(new FixedTenantStore("acme", "globex"));
                services.AddScoped(_ => engine);
                services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                    .AddCookie()
                    .AddJwtBearer("Bearer", o => o.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = Key,
                        ValidAlgorithms = [SecurityAlgorithms.HmacSha256]
                    });
                services.AddAuthorization();
                services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();
                services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();
            },
            app =>
            {
                app.UseAuthentication();
                app.UseTenantResolution();
                app.UseAuthorization();
                app.MapGet("/api/who", (TenantContext tenant) => Results.Text(tenant.TenantId ?? "none"))
                    .AllowAnonymous();
                app.MapGet("/api/reports", () => Results.Text("reports"))
                    .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = "Bearer" }, new AuthorizeAttribute("sales.view"));
            });

    private static HttpRequestMessage Get(string path, string? bearer = null, string? header = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (bearer != null) request.Headers.Authorization = new("Bearer", bearer);
        if (header != null) request.Headers.Add("TenantId", header);
        return request;
    }

    [Fact]
    public async Task AnonymousEndpoint_ShouldTakeTheTenantFromTheHeader_EvenWhenABearerTokenIsSent_BecauseNoBearerSchemeRunsThere()
    {
        var engine = Substitute.For<ISecurityEngine>();
        await using var host = await StartCookieDefaultAsync(engine);

        var who = await host.Client.SendAsync(Get("/api/who", bearer: BearerFor("acme"), header: "globex"));

        // The endpoint asks for no authentication, so nobody is authenticated and the header is the only source.
        who.StatusCode.Should().Be(HttpStatusCode.OK);
        (await who.Content.ReadAsStringAsync()).Should().Be("globex");
    }

    [Fact]
    public async Task PermissionEndpoint_ShouldAnswer403_WhenTheBearerTenantIsAcmeAndTheHeaderNamesGlobex()
    {
        var engine = Substitute.For<ISecurityEngine>();
        engine.CanAccessAsync(Arg.Any<string>(), Arg.Any<string>()).Returns(true);
        await using var host = await StartCookieDefaultAsync(engine);

        var response = await host.Client.SendAsync(Get("/api/reports", bearer: BearerFor("acme"), header: "globex"));

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        await engine.DidNotReceiveWithAnyArgs().CanAccessAsync(default!, default!);
    }

    [Fact]
    public async Task PermissionEndpoint_ShouldAnswer400TenantRequired_WhenTheBearerIsValidButNoTenantHeaderIsSent_AndTheDefaultSchemeIsACookie()
    {
        var engine = Substitute.For<ISecurityEngine>();
        engine.CanAccessAsync(Arg.Any<string>(), Arg.Any<string>()).Returns(true);
        await using var host = await StartCookieDefaultAsync(engine);

        var response = await host.Client.SendAsync(Get("/api/reports", bearer: BearerFor("acme")));

        // The cookie default authenticates nobody, so the middleware sees no tenant source on a path that needs one.
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        await engine.DidNotReceiveWithAnyArgs().CanAccessAsync(default!, default!);
    }

    [Fact]
    public async Task PermissionEndpoint_ShouldAnswer401_WhenThereIsNoCredentialAtAll()
    {
        var engine = Substitute.For<ISecurityEngine>();
        await using var host = await StartCookieDefaultAsync(engine);

        var response = await host.Client.SendAsync(Get("/api/reports", header: "acme"));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    // Positive control with the library's own wiring (the bearer scheme is the default one): the claim is the tenant,
    // a header naming another tenant is ignored, and the permission handler lets the matching request through.
    [Fact]
    public async Task LibraryWiring_ShouldAnswer200_WhenTheClaimMatchesTheResolvedTenant_AndIgnoreTheHeader()
    {
        var engine = Substitute.For<ISecurityEngine>();
        engine.CanAccessAsync("SALES", "VIEW").Returns(true);
        await using var host = await InProcessHost.StartAsync(
            builder =>
            {
                builder.Services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase("credential-pipeline"));
                builder.Services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(o =>
                {
                    o.Jwt.Secret = "credential-pipeline-signing-key-32-bytes!!";
                    o.Jwt.Issuer = "iss";
                    o.Jwt.Audience = "aud";
                    o.AllowUnverifiedTenantMembership = true;
                });
                builder.Services.AddHostStubs(new FixedTenantStore("acme", "globex"));
                builder.Services.AddScoped(_ => engine);
            },
            app =>
            {
                app.UseAuthentication();
                app.UseTenantResolution();
                app.UseAuthorization();
                app.MapGet("/api/reports", (TenantContext tenant) => Results.Text(tenant.TenantId ?? "none"))
                    .RequireAuthorization("sales.view");
            });
        var token = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            "iss", "aud",
            [new Claim("tenant_id", "acme"), new Claim("sub", "user-1")],
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey("credential-pipeline-signing-key-32-bytes!!"u8.ToArray()), SecurityAlgorithms.HmacSha256)));

        var response = await host.Client.SendAsync(Get("/api/reports", bearer: token, header: "globex"));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync()).Should().Be("acme");
    }
}
