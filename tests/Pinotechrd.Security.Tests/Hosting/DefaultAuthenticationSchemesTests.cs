using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Options;
using Xunit;

namespace Pinotechrd.Security.Tests.Hosting;

/// <summary>
/// <see cref="PinotechrdSecurityOptions.SetDefaultAuthenticationSchemes"/>: whether AddPinotechrdSecurity makes JwtBearer
/// the default authenticate and challenge scheme, or leaves the host's defaults alone. The host registers a second
/// scheme (cookies), because with JwtBearer alone ASP.NET Core picks it as the default by itself.
/// </summary>
public class DefaultAuthenticationSchemesTests
{
    private const string Secret = "default-schemes-test-secret-key-32-bytes!!";
    private const string Cookies = "Cookies";

    private static void AddSecurity(IServiceCollection services, Action<PinotechrdSecurityOptions>? extra = null) =>
        services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(o =>
        {
            o.Jwt.Secret = Secret;
            o.Jwt.Issuer = "the-issuer";
            o.Jwt.Audience = "the-audience";
            o.AllowUnverifiedTenantMembership = true;
            extra?.Invoke(o);
        });

    private static void AddHostCookies(IServiceCollection services) =>
        services.AddAuthentication(Cookies).AddCookie(Cookies);

    private static Task<InProcessHost> StartAsync(
        Action<IServiceCollection> configure,
        Action<WebApplication>? pipeline = null) =>
        InProcessHost.StartAsync(
            builder =>
            {
                var databaseName = Guid.NewGuid().ToString();
                builder.Services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(databaseName));
                configure(builder.Services);
                builder.Services.AddHostStubs();
            },
            app =>
            {
                if (pipeline != null)
                {
                    pipeline(app);
                    return;
                }

                app.UseAuthentication();
                app.UseAuthorization();
                app.MapGet("/bearer-only", [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)] () => Results.Ok());
            });

    private static async Task<(string? Authenticate, string? Challenge, bool JwtRegistered)> ResolveAsync(InProcessHost host)
    {
        var schemes = host.Services.GetRequiredService<IAuthenticationSchemeProvider>();
        return ((await schemes.GetDefaultAuthenticateSchemeAsync())?.Name,
            (await schemes.GetDefaultChallengeSchemeAsync())?.Name,
            await schemes.GetSchemeAsync(JwtBearerDefaults.AuthenticationScheme) != null);
    }

    private static string Token()
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret));
        var token = new JwtSecurityToken(
            "the-issuer", "the-audience", [new Claim("sub", "user-1")], expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static Task<HttpResponseMessage> GetAsync(InProcessHost host, string path, string? bearer)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (bearer != null) request.Headers.Authorization = new("Bearer", bearer);
        return host.Client.SendAsync(request);
    }

    [Fact]
    public async Task FlagFalse_ShouldKeepTheHostCookieDefaults_AndStillRegisterJwtBearer()
    {
        await using var host = await StartAsync(services =>
        {
            AddHostCookies(services);
            AddSecurity(services, o => o.SetDefaultAuthenticationSchemes = false);
        });

        var (authenticate, challenge, jwtRegistered) = await ResolveAsync(host);

        authenticate.Should().Be(Cookies);
        challenge.Should().Be(Cookies);
        jwtRegistered.Should().BeTrue();
    }

    [Fact]
    public async Task FlagFalse_ShouldKeepTheHostDefaults_WhenTheHostRegistersCookiesAfterTheLibrary()
    {
        await using var host = await StartAsync(services =>
        {
            AddSecurity(services, o => o.SetDefaultAuthenticationSchemes = false);
            AddHostCookies(services);
        });

        var (authenticate, challenge, _) = await ResolveAsync(host);

        authenticate.Should().Be(Cookies);
        challenge.Should().Be(Cookies);
    }

    [Fact]
    public async Task FlagFalse_ShouldStillAuthenticateABearerToken_OnAnEndpointThatNamesTheBearerScheme()
    {
        await using var host = await StartAsync(services =>
        {
            AddHostCookies(services);
            AddSecurity(services, o => o.SetDefaultAuthenticationSchemes = false);
        });

        (await GetAsync(host, "/bearer-only", Token())).StatusCode.Should().Be(HttpStatusCode.OK);
        (await GetAsync(host, "/bearer-only", "not-a-token")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await GetAsync(host, "/bearer-only", null)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task FlagTrue_ByDefault_ShouldMakeJwtBearerTheDefault_EvenWhenTheHostRegistersCookiesFirst()
    {
        await using var host = await StartAsync(services =>
        {
            AddHostCookies(services);
            AddSecurity(services);
        });

        var (authenticate, challenge, jwtRegistered) = await ResolveAsync(host);

        authenticate.Should().Be(JwtBearerDefaults.AuthenticationScheme);
        challenge.Should().Be(JwtBearerDefaults.AuthenticationScheme);
        jwtRegistered.Should().BeTrue();
    }

    [Fact]
    public void SetDefaultAuthenticationSchemes_ShouldDefaultToTrue() =>
        new PinotechrdSecurityOptions().SetDefaultAuthenticationSchemes.Should().BeTrue();

    [Fact]
    public async Task FlagFalse_SetByALaterConfigureOfTheOptions_ShouldBeHonoured()
    {
        await using var host = await StartAsync(services =>
        {
            AddHostCookies(services);
            AddSecurity(services);
            services.Configure<PinotechrdSecurityOptions>(o => o.SetDefaultAuthenticationSchemes = false);
        });

        var (authenticate, challenge, jwtRegistered) = await ResolveAsync(host);

        authenticate.Should().Be(Cookies);
        challenge.Should().Be(Cookies);
        jwtRegistered.Should().BeTrue();
    }

    [Fact]
    public async Task FlagTrue_SetByALaterConfigureOfTheOptions_ShouldOverrideAnEarlierFalse()
    {
        await using var host = await StartAsync(services =>
        {
            AddHostCookies(services);
            AddSecurity(services, o => o.SetDefaultAuthenticationSchemes = false);
            services.Configure<PinotechrdSecurityOptions>(o => o.SetDefaultAuthenticationSchemes = true);
        });

        (await ResolveAsync(host)).Authenticate.Should().Be(JwtBearerDefaults.AuthenticationScheme);
    }

    [Fact]
    public async Task FlagFalse_SetByConfigurationBinding_ShouldBeHonoured()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Security:SetDefaultAuthenticationSchemes"] = "false" })
            .Build();
        await using var host = await StartAsync(services =>
        {
            AddHostCookies(services);
            AddSecurity(services);
            services.Configure<PinotechrdSecurityOptions>(configuration.GetSection("Security"));
        });

        var (authenticate, challenge, _) = await ResolveAsync(host);

        authenticate.Should().Be(Cookies);
        challenge.Should().Be(Cookies);
    }

    [Fact]
    public async Task HostConfigureOfAuthenticationOptions_RegisteredAfterTheLibrary_ShouldWinOverTheLibraryDefaults()
    {
        await using var host = await StartAsync(services =>
        {
            AddHostCookies(services);
            AddSecurity(services);
            services.Configure<AuthenticationOptions>(o =>
            {
                o.DefaultAuthenticateScheme = Cookies;
                o.DefaultChallengeScheme = Cookies;
            });
        });

        var (authenticate, challenge, _) = await ResolveAsync(host);

        authenticate.Should().Be(Cookies);
        challenge.Should().Be(Cookies);
    }

    [Fact]
    public async Task FlagFalse_ShouldKeepAnExplicitHostAuthenticateAndChallengeScheme_SetBeforeTheLibrary()
    {
        await using var host = await StartAsync(services =>
        {
            AddHostCookies(services);
            services.Configure<AuthenticationOptions>(o =>
            {
                o.DefaultAuthenticateScheme = Cookies;
                o.DefaultChallengeScheme = Cookies;
            });
            AddSecurity(services, o => o.SetDefaultAuthenticationSchemes = false);
        });

        var (authenticate, challenge, _) = await ResolveAsync(host);

        authenticate.Should().Be(Cookies);
        challenge.Should().Be(Cookies);
    }

    [Fact]
    public async Task FlagFalse_ShouldNotLeaveIdentityExternalAsTheDefaultSignInScheme_SoTheHostDefaultSchemeApplies()
    {
        await using var host = await StartAsync(services =>
        {
            AddHostCookies(services);
            AddSecurity(services, o => o.SetDefaultAuthenticationSchemes = false);
        });

        var schemes = host.Services.GetRequiredService<IAuthenticationSchemeProvider>();
        var options = host.Services.GetRequiredService<IOptions<AuthenticationOptions>>().Value;

        options.DefaultSignInScheme.Should().NotBe("Identity.External");
        (await schemes.GetDefaultSignInSchemeAsync())!.Name.Should().Be(Cookies);
    }

    [Fact]
    public async Task WithoutAnyJwtConfiguration_ResolvingTheAuthenticationOptions_ShouldNotThrow_AndDefaultToJwtBearer()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>();
        using var provider = services.BuildServiceProvider();

        var act = () => provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;

        var options = act.Should().NotThrow().Subject;
        options.DefaultAuthenticateScheme.Should().Be(JwtBearerDefaults.AuthenticationScheme);
        options.DefaultChallengeScheme.Should().Be(JwtBearerDefaults.AuthenticationScheme);
        var schemes = provider.GetRequiredService<IAuthenticationSchemeProvider>();
        (await schemes.GetDefaultAuthenticateSchemeAsync())!.Name.Should().Be(JwtBearerDefaults.AuthenticationScheme);
    }

    [Fact]
    public async Task FlagFalse_ShouldResolveTheTenantFromTheClaimOfACookiePrincipal_WithoutATenantHeader()
    {
        await using var host = await StartAsync(
            services =>
            {
                AddHostCookies(services);
                AddSecurity(services, o => o.SetDefaultAuthenticationSchemes = false);
            },
            app =>
            {
                app.UseAuthentication();
                app.UseTenantResolution();
                app.UseAuthorization();
                app.MapGet("/login/{tenant}", async (HttpContext http, string tenant) =>
                {
                    var identity = new ClaimsIdentity([new Claim("sub", "user-1"), new Claim("tenant_id", tenant)], Cookies);
                    await http.SignInAsync(Cookies, new ClaimsPrincipal(identity));
                    return Results.Ok();
                }).AllowAnonymous();
                app.MapGet("/api/who", [Authorize] (TenantContext tenant) => Results.Text(tenant.TenantId ?? "none"));
            });

        var login = await host.Client.GetAsync("/login/tenant-a");
        var cookie = login.Headers.GetValues("Set-Cookie").Single().Split(';')[0];

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/who");
        request.Headers.Add("Cookie", cookie);
        var who = await host.Client.SendAsync(request);

        who.StatusCode.Should().Be(HttpStatusCode.OK);
        (await who.Content.ReadAsStringAsync()).Should().Be("tenant-a");
    }

    // WebApplication adds UseAuthentication() by itself when a scheme is registered, so the ordering guard is
    // exercised by invoking the middleware directly over the services AddPinotechrdSecurity registers.
    private static async Task<Exception?> InvokeWithoutUseAuthenticationAsync(bool setDefaults, bool withHostCookies)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        if (withHostCookies) AddHostCookies(services);
        AddSecurity(services, o => o.SetDefaultAuthenticationSchemes = setDefaults);

        var context = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        context.Request.Path = "/api/x";
        context.Request.Headers["TenantId"] = "tenant-a";
        context.Response.Body = new MemoryStream();

        var store = Substitute.For<ITenantStore>();
        store.TenantExistsAsync("tenant-a").Returns(true);
        var middleware = new TenantResolutionMiddleware(
            _ => Task.CompletedTask,
            new TenantResolutionOptions(),
            Substitute.For<ILogger<TenantResolutionMiddleware>>());

        try
        {
            await middleware.InvokeAsync(context, new TenantContext(), store);
            return null;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task TenantResolution_ShouldThrowTheOrderingError_WhenUseAuthenticationWasNotCalled(bool setDefaults, bool withHostCookies)
    {
        var error = await InvokeWithoutUseAuthenticationAsync(setDefaults, withHostCookies);

        error.Should().BeOfType<InvalidOperationException>().Which.Message.Should().Contain("UseAuthentication");
    }
}
