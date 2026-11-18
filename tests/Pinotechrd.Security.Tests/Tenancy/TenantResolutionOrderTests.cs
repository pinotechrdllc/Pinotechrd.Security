using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Tenancy;

/// <summary>
/// The middleware must run after authentication, otherwise every authenticated request looks anonymous and
/// would take its tenant from the header. It detects the wrong order instead of silently trusting the header.
/// </summary>
public class TenantResolutionOrderTests
{
    private static readonly SymmetricSecurityKey Key =
        new("order-test-signing-key-minimum-length-32!"u8.ToArray());

    private sealed class NoopHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public NoopHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync() => Task.FromResult(AuthenticateResult.NoResult());
    }

    private sealed class FakeAuthenticationFeature : IAuthenticationFeature
    {
        public PathString OriginalPathBase { get; set; }

        public PathString OriginalPath { get; set; }
    }

    private static async Task<Exception?> InvokeAsync(
        Action<IServiceCollection>? configure,
        bool withFeature,
        ClaimsPrincipal? user = null,
        TenantResolutionOptions? options = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        configure?.Invoke(services);

        var context = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        context.Request.Path = "/api/x";
        context.Request.Headers["TenantId"] = "tenant-a";
        context.Response.Body = new MemoryStream();
        if (withFeature) context.Features.Set<IAuthenticationFeature>(new FakeAuthenticationFeature());
        if (user != null) context.User = user;

        var store = Substitute.For<ITenantStore>();
        store.TenantExistsAsync("tenant-a").Returns(true);
        var middleware = new TenantResolutionMiddleware(
            _ => Task.CompletedTask,
            options ?? new TenantResolutionOptions(),
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

    private static void WithDefaultScheme(IServiceCollection services) =>
        services.AddAuthentication("test").AddScheme<AuthenticationSchemeOptions, NoopHandler>("test", null);

    // ---- Unit: the detection rule ------------------------------------------------------------

    [Fact]
    public async Task InvokeAsync_ShouldThrowNamingUseAuthentication_WhenAnonymousHeaderRequestRunsBeforeAuthentication()
    {
        var error = await InvokeAsync(WithDefaultScheme, withFeature: false);

        error.Should().BeOfType<InvalidOperationException>();
        error!.Message.Should().Contain("UseAuthentication");
    }

    [Fact]
    public async Task InvokeAsync_ShouldNotThrow_WhenAuthenticationAlreadyRan()
    {
        var error = await InvokeAsync(WithDefaultScheme, withFeature: true);

        error.Should().BeNull();
    }

    [Fact]
    public async Task InvokeAsync_ShouldNotThrow_WhenNoAuthenticationSchemeProviderIsRegistered()
    {
        var error = await InvokeAsync(configure: null, withFeature: false);

        error.Should().BeNull();
    }

    [Fact]
    public async Task InvokeAsync_ShouldNotThrow_WhenAuthenticationHasNoDefaultScheme()
    {
        var error = await InvokeAsync(
            services => services.AddAuthentication()
                .AddScheme<AuthenticationSchemeOptions, NoopHandler>("one", null)
                .AddScheme<AuthenticationSchemeOptions, NoopHandler>("two", null),
            withFeature: false);

        error.Should().BeNull();
    }

    [Fact]
    public async Task InvokeAsync_ShouldNotThrow_WhenTheUserIsAlreadyAuthenticated()
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("tenant_id", "tenant-a")], "Bearer"));

        var error = await InvokeAsync(WithDefaultScheme, withFeature: false, user: user);

        error.Should().BeNull();
    }

    [Theory]
    [InlineData(TenantSources.Claim)]
    [InlineData(TenantSources.None)]
    public async Task InvokeAsync_ShouldNotThrow_WhenTheHeaderIsNotASource(TenantSources sources)
    {
        var error = await InvokeAsync(WithDefaultScheme, withFeature: false, options: new TenantResolutionOptions { Sources = sources });

        error.Should().BeNull();
    }

    // ---- Real pipeline with a real JWT bearer scheme -----------------------------------------

    private static string BearerToken(string tenant)
    {
        var token = new JwtSecurityToken(
            claims: [new Claim("tenant_id", tenant), new Claim("sub", "user-1")],
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(Key, SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static Task<InProcessHost> StartAsync(bool authenticationFirst) =>
        InProcessHost.StartAsync(
            builder =>
            {
                builder.Services.AddScoped<TenantContext>();
                builder.Services.AddSingleton(new TenantResolutionOptions());
                builder.Services.AddSingleton<ITenantStore>(new FixedTenantStore("tenant-a", "tenant-b"));
                builder.Services.AddAuthentication("Bearer").AddJwtBearer("Bearer", o =>
                {
                    o.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = Key,
                        ValidAlgorithms = [SecurityAlgorithms.HmacSha256]
                    };
                });
                builder.Services.AddAuthorization();
            },
            app =>
            {
                if (authenticationFirst)
                {
                    app.UseAuthentication();
                    app.UseTenantResolution();
                }
                else
                {
                    app.UseTenantResolution();
                    app.UseAuthentication();
                }
                app.UseAuthorization();
                app.MapGet("/api/who", (TenantContext tenant) => Results.Text(tenant.TenantId ?? "none"));
            });

    private static HttpRequestMessage Get(string? header = null, string? bearer = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/who");
        if (header != null) request.Headers.Add("TenantId", header);
        if (bearer != null) request.Headers.Authorization = new("Bearer", bearer);
        return request;
    }

    [Fact]
    public async Task Pipeline_ShouldFail_WhenTenantResolutionIsBeforeAuthentication()
    {
        await using var host = await StartAsync(authenticationFirst: false);

        var anonymous = await host.Client.SendAsync(Get(header: "tenant-b"));
        var bearer = await host.Client.SendAsync(Get(header: "tenant-b", bearer: BearerToken("tenant-a")));

        anonymous.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        bearer.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
    }

    [Fact]
    public async Task Pipeline_ShouldWork_WhenAuthenticationIsBeforeTenantResolution()
    {
        await using var host = await StartAsync(authenticationFirst: true);

        var anonymous = await host.Client.SendAsync(Get(header: "tenant-b"));
        var bearer = await host.Client.SendAsync(Get(header: "tenant-b", bearer: BearerToken("tenant-a")));
        var noTenant = await host.Client.SendAsync(Get());

        anonymous.StatusCode.Should().Be(HttpStatusCode.OK);
        (await anonymous.Content.ReadAsStringAsync()).Should().Be("tenant-b");
        bearer.StatusCode.Should().Be(HttpStatusCode.OK);
        (await bearer.Content.ReadAsStringAsync()).Should().Be("tenant-a");
        noTenant.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Pipeline_ShouldTreatAnInvalidBearerTokenAsAnonymous_AndUseTheHeader()
    {
        await using var host = await StartAsync(authenticationFirst: true);

        var response = await host.Client.SendAsync(Get(header: "tenant-b", bearer: BearerToken("tenant-a") + "x"));

        // A token that fails validation does not authenticate: the request is anonymous, so only the header applies.
        (await response.Content.ReadAsStringAsync()).Should().Be("tenant-b");
    }
}
