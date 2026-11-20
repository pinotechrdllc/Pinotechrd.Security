using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Xunit;

namespace Pinotechrd.Security.Tests.Hosting;

/// <summary>
/// The default data provider behind the real bearer handler: a token the application fails in its own
/// <c>OnTokenValidated</c> names nobody, even when another scheme authenticates the request; and an application's own
/// provider replaces the default.
/// </summary>
public class DefaultSecurityDataProviderHostTests
{
    private const string Secret = "default-provider-host-tests-secret-32b!!";
    private const string Issuer = "iss";

    private static string Token(string userId, bool blocked = false)
    {
        var claims = new List<Claim> { new("id", userId), new("tenant_id", "a") };
        if (blocked) claims.Add(new Claim("blocked", "true"));
        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            Issuer, "aud", claims, expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(Secret)), SecurityAlgorithms.HmacSha256)));
    }

    private static Task<InProcessHost> StartAsync(Action<IServiceCollection>? configure = null) =>
        InProcessHost.StartAsync(
            builder =>
            {
                var services = builder.Services;
                services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));
                // The application's own rule: some tokens are refused after the library validated them.
                services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, o => o.Events = new JwtBearerEvents
                {
                    OnTokenValidated = context =>
                    {
                        if (context.Principal?.HasClaim("blocked", "true") == true) context.Fail("blocked by the application");
                        return Task.CompletedTask;
                    },
                });
                services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(o =>
                {
                    o.Jwt.Secret = Secret;
                    o.Jwt.Issuer = Issuer;
                    o.Jwt.Audience = "aud";
                    o.Jwt.ValidateSecurityStamp = false;
                    o.AllowUnverifiedTenantMembership = true;
                });
                services.AddSingleton<ITenantStore>(new FixedTenantStore("a"));
                services.AddAuthentication().AddCookie("C");
                configure?.Invoke(services);
            },
            app =>
            {
                app.UseAuthentication();
                app.UseTenantResolution();
                app.UseAuthorization();
                app.MapPost("/signin", async (HttpContext http) =>
                {
                    await http.SignInAsync("C", new ClaimsPrincipal(new ClaimsIdentity([new Claim("tenant_id", "a"), new Claim("id", "cookie-user")], "C")));
                    return Results.Ok();
                });
                app.MapGet("/who", [Authorize(AuthenticationSchemes = "Bearer,C")] (ISecurityDataProvider provider) =>
                    Results.Text(provider.GetCurrentUserId() ?? "<none>"));
            });

    private static async Task<string> WhoAsync(InProcessHost host, string? bearer, string? cookie)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/who");
        request.Headers.Add("TenantId", "a");
        if (bearer != null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (cookie != null) request.Headers.Add("Cookie", cookie);
        var response = await host.Client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return await response.Content.ReadAsStringAsync();
    }

    private static async Task<string> CookieAsync(InProcessHost host)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/signin");
        request.Headers.Add("TenantId", "a");
        var response = await host.Client.SendAsync(request);
        return string.Join("; ", response.Headers.GetValues("Set-Cookie").Select(c => c.Split(';')[0]));
    }

    [Fact]
    public async Task ALibraryToken_ShouldNameItsUser()
    {
        await using var host = await StartAsync();

        (await WhoAsync(host, Token("token-user"), cookie: null)).Should().Be("token-user");
    }

    [Fact]
    public async Task ATokenTheApplicationFailed_ShouldNameNobody_EvenWithAnotherSchemesIdentity()
    {
        await using var host = await StartAsync();
        var cookie = await CookieAsync(host);

        (await WhoAsync(host, Token("token-user", blocked: true), cookie)).Should().Be("<none>",
            "the failed token is not recorded, and the cookie's id claim is not the library's");
        (await WhoAsync(host, bearer: null, cookie)).Should().Be("<none>", "a cookie identity alone names no user for the default provider");
    }

    [Fact]
    public async Task AnApplicationsOwnProvider_ShouldReplaceTheDefault_RegisteredAfterTheLibrary()
    {
        var own = Substitute.For<ISecurityDataProvider>();
        own.GetCurrentUserId().Returns("from-own-provider");
        await using var host = await StartAsync(s => s.AddScoped(_ => own));

        (await WhoAsync(host, Token("token-user"), cookie: null)).Should().Be("from-own-provider");
    }
}
