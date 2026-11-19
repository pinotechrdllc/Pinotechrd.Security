using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Tenancy;

public sealed class ExecutionCounter
{
    private int _count;

    public int Count => Volatile.Read(ref _count);

    public void Hit() => Interlocked.Increment(ref _count);
}

public sealed record MarkerMetadata(string Value);

/// <summary>An MVC controller whose endpoint accepts only the cookie scheme "C".</summary>
[ApiController]
[Route("api/mvc")]
[Authorize(AuthenticationSchemes = "C")]
public sealed class TenantProbeController : ControllerBase
{
    [HttpGet]
    public IActionResult Get([FromServices] ExecutionCounter counter, [FromServices] TenantContext tenant)
    {
        counter.Hit();
        return Content(tenant.TenantId ?? "none");
    }

    [HttpGet("anonymous")]
    [AllowAnonymous]
    public IActionResult Anonymous([FromServices] ExecutionCounter counter, [FromServices] TenantContext tenant)
    {
        counter.Hit();
        return Content(tenant.TenantId ?? "none");
    }
}

/// <summary>
/// The consistency check that <c>UseTenantResolution</c> puts in front of every routed endpoint: once authorization has added
/// the endpoint's schemes to the user, an authenticated tenant claim must equal the resolved tenant.
/// </summary>
public class TenantConsistencyCheckTests
{
    private static readonly SymmetricSecurityKey Key = new("consistency-check-signing-key-32-bytes!!"u8.ToArray());

    private sealed class NoopHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public NoopHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync() => Task.FromResult(AuthenticateResult.NoResult());
    }

    private sealed class CapturingProvider : ILoggerProvider
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public ILogger CreateLogger(string categoryName) => new Capture(this);

        public void Dispose()
        {
        }

        private sealed class Capture(CapturingProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                lock (owner.Entries) owner.Entries.Add((logLevel, formatter(state, exception)));
            }
        }
    }

    private sealed record Started(InProcessHost Host, ExecutionCounter Counter, CapturingProvider Logs) : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => Host.DisposeAsync();
    }

    private static string Bearer(string tenant)
    {
        var token = new JwtSecurityToken(
            claims: [new Claim("tenant_id", tenant), new Claim("sub", "user-1")],
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(Key, SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>Default scheme authenticates nobody; "C" is a cookie scheme and "Bearer" a JWT scheme, neither of them default.</summary>
    private static async Task<Started> StartAsync(bool routingAfterMiddleware = false, Action<TenantResolutionOptions>? configure = null)
    {
        var counter = new ExecutionCounter();
        var logs = new CapturingProvider();
        var options = new TenantResolutionOptions();
        configure?.Invoke(options);

        var host = await InProcessHost.StartAsync(
            builder =>
            {
                var services = builder.Services;
                builder.Logging.AddProvider(logs);
                services.AddSingleton(counter);
                services.AddScoped<TenantContext>();
                services.AddSingleton(options);
                services.AddSingleton<ITenantStore>(new FixedTenantStore("a", "b"));
                services.AddProblemDetails();
                services.AddControllers().AddApplicationPart(typeof(TenantProbeController).Assembly);
                services.AddAuthentication("Anon")
                    .AddScheme<AuthenticationSchemeOptions, NoopHandler>("Anon", null)
                    .AddCookie("C", o =>
                    {
                        o.Cookie.Name = "c";
                        o.Events.OnRedirectToLogin = ctx => { ctx.Response.StatusCode = 401; return Task.CompletedTask; };
                    })
                    .AddJwtBearer("Bearer", o => o.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = Key,
                        ValidAlgorithms = [SecurityAlgorithms.HmacSha256]
                    });
                services.AddAuthorization();
            },
            app =>
            {
                app.UseAuthentication();
                app.UseTenantResolution();
                if (routingAfterMiddleware) app.UseRouting();
                app.UseAuthorization();

                app.MapPost("/signin/{tenant}", async (string tenant, HttpContext http) =>
                {
                    var identity = new ClaimsIdentity([new Claim("tenant_id", tenant), new Claim("sub", "user-1")], "C");
                    await http.SignInAsync("C", new ClaimsPrincipal(identity));
                    return Results.Ok();
                });

                app.MapGet("/api/c", (ExecutionCounter c, TenantContext t) => { c.Hit(); return Results.Text(t.TenantId ?? "none"); })
                    .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = "C" });
                app.MapGet("/api/bearer", (ExecutionCounter c, TenantContext t) => { c.Hit(); return Results.Text(t.TenantId ?? "none"); })
                    .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = "Bearer" });
                app.MapGet("/api/both", (ExecutionCounter c, TenantContext t) => { c.Hit(); return Results.Text(t.TenantId ?? "none"); })
                    .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = "C,Bearer" });
                app.MapGet("/api/anon", (ExecutionCounter c, TenantContext t) => { c.Hit(); return Results.Text(t.TenantId ?? "none"); })
                    .AllowAnonymous();
                app.MapGet("/skip/c", (ExecutionCounter c, TenantContext t) => { c.Hit(); return Results.Text(t.TenantId ?? "none"); })
                    .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = "C" });
                app.MapGet("/api/meta", (HttpContext http) =>
                    {
                        var endpoint = http.GetEndpoint()!;
                        var route = endpoint as RouteEndpoint;
                        return Results.Json(new
                        {
                            display = endpoint.DisplayName,
                            pattern = route?.RoutePattern.RawText,
                            order = route?.Order,
                            marker = endpoint.Metadata.GetMetadata<MarkerMetadata>()?.Value,
                            hasName = endpoint.Metadata.GetMetadata<IEndpointNameMetadata>()?.EndpointName
                        });
                    })
                    .WithName("meta-endpoint")
                    .WithDisplayName("the-original-display-name")
                    .WithMetadata(new MarkerMetadata("original"))
                    .Add(b => ((RouteEndpointBuilder)b).Order = 7);
                app.MapControllers();
            });

        return new Started(host, counter, logs);
    }

    private static async Task SignInAsync(HttpClient client, string tenant)
    {
        var response = await client.PostAsync($"/signin/{tenant}", null);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    private static HttpRequestMessage Get(string path, string? header = null, string? bearer = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (header != null) request.Headers.Add("TenantId", header);
        if (bearer != null) request.Headers.Authorization = new("Bearer", bearer);
        return request;
    }

    private static async Task AssertTenantInvalidAsync(HttpResponseMessage response)
    {
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/problem+json");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        json.RootElement.GetProperty("code").GetString().Should().Be("tenant_invalid");
    }

    // ---- A mismatching authenticated user never reaches the endpoint ------------------------

    [Theory]
    [InlineData("/api/c")]
    [InlineData("/api/mvc")]
    public async Task Endpoint_ShouldAnswer400TenantInvalid_AndNotRun_WhenTheCookieTenantDiffersFromTheHeader(string path)
    {
        await using var app = await StartAsync();
        await SignInAsync(app.Host.Client, "a");

        var response = await app.Host.Client.SendAsync(Get(path, header: "b"));

        await AssertTenantInvalidAsync(response);
        app.Counter.Count.Should().Be(0, "the endpoint body must not run");
    }

    [Theory]
    [InlineData("/api/c")]
    [InlineData("/api/mvc")]
    public async Task Endpoint_ShouldRun_WhenTheCookieTenantEqualsTheHeader(string path)
    {
        await using var app = await StartAsync();
        await SignInAsync(app.Host.Client, "a");

        var response = await app.Host.Client.SendAsync(Get(path, header: "a"));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync()).Should().Be("a");
        app.Counter.Count.Should().Be(1);
    }

    [Fact]
    public async Task AnonymousEndpoint_ShouldRunWithoutACheck_WhenNobodyIsAuthenticatedThere()
    {
        await using var app = await StartAsync();
        await SignInAsync(app.Host.Client, "a");

        var response = await app.Host.Client.SendAsync(Get("/api/anon", header: "b"));

        // Cookie "C" is not the default and the endpoint asks for no scheme, so nobody is authenticated: header b is the tenant.
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync()).Should().Be("b");
    }

    // [AllowAnonymous] on an action does not stop authorization from authenticating the schemes of the controller's
    // [Authorize]: the user is authenticated for tenant a, so the check applies and rejects tenant b.
    [Fact]
    public async Task AllowAnonymousAction_ShouldStillBeRejected_WhenTheControllersSchemeAuthenticatesAnotherTenant()
    {
        await using var app = await StartAsync();
        await SignInAsync(app.Host.Client, "a");

        var mismatch = await app.Host.Client.SendAsync(Get("/api/mvc/anonymous", header: "b"));
        var match = await app.Host.Client.SendAsync(Get("/api/mvc/anonymous", header: "a"));

        await AssertTenantInvalidAsync(mismatch);
        match.StatusCode.Should().Be(HttpStatusCode.OK);
        app.Counter.Count.Should().Be(1);
    }

    [Fact]
    public async Task AllowAnonymousEndpoint_ShouldStillBeChecked_WhenALaterStepAuthenticatesAnotherTenantsUser()
    {
        var counter = new ExecutionCounter();
        await using var host = await InProcessHost.StartAsync(
            builder =>
            {
                var services = builder.Services;
                services.AddSingleton(counter);
                services.AddScoped<TenantContext>();
                services.AddSingleton(new TenantResolutionOptions());
                services.AddSingleton<ITenantStore>(new FixedTenantStore("a", "b"));
                services.AddProblemDetails();
                services.AddAuthentication("Anon").AddScheme<AuthenticationSchemeOptions, NoopHandler>("Anon", null);
                services.AddAuthorization();
            },
            app =>
            {
                app.UseAuthentication();
                app.UseTenantResolution();
                // Something after the tenant middleware authenticates a user of tenant a (a custom step, a second pipeline, ...).
                app.Use(async (context, next) =>
                {
                    context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("tenant_id", "a")], "Custom"));
                    await next();
                });
                app.UseAuthorization();
                app.MapGet("/api/anon", (ExecutionCounter c) => { c.Hit(); return Results.Ok(); }).AllowAnonymous();
            });

        var mismatch = await host.Client.SendAsync(Get("/api/anon", header: "b"));
        var match = await host.Client.SendAsync(Get("/api/anon", header: "a"));

        await AssertTenantInvalidAsync(mismatch);
        match.StatusCode.Should().Be(HttpStatusCode.OK);
        counter.Count.Should().Be(1);
    }

    // ---- Bearer ------------------------------------------------------------------------------

    [Fact]
    public async Task NonDefaultBearerEndpoint_ShouldAnswer400_WhenTheTokenTenantDiffersFromTheHeader()
    {
        await using var app = await StartAsync();

        var response = await app.Host.Client.SendAsync(Get("/api/bearer", header: "b", bearer: Bearer("a")));

        await AssertTenantInvalidAsync(response);
        app.Counter.Count.Should().Be(0);
    }

    [Fact]
    public async Task NonDefaultBearerEndpoint_ShouldRun_WhenTheTokenTenantEqualsTheHeader()
    {
        await using var app = await StartAsync();

        var response = await app.Host.Client.SendAsync(Get("/api/bearer", header: "a", bearer: Bearer("a")));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync()).Should().Be("a");
    }

    [Fact]
    public async Task DefaultBearer_ShouldStayInTheClaimTenantAndSucceed_WhenTheHeaderNamesAnotherTenant()
    {
        var counter = new ExecutionCounter();
        await using var host = await InProcessHost.StartAsync(
            builder =>
            {
                builder.Services.AddSingleton(counter);
                builder.Services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase("consistency-default-bearer"));
                builder.Services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(o =>
                {
                    o.Jwt.Secret = "consistency-check-signing-key-32-bytes!!";
                    o.Jwt.Issuer = "iss";
                    o.Jwt.Audience = "aud";
                    o.AllowUnverifiedTenantMembership = true;
                });
                builder.Services.AddHostStubs(new FixedTenantStore("a", "b"));
            },
            app =>
            {
                app.UseAuthentication();
                app.UseTenantResolution();
                app.UseAuthorization();
                app.MapGet("/api/plain", (ExecutionCounter c, TenantContext t) => { c.Hit(); return Results.Text(t.TenantId ?? "none"); })
                    .RequireAuthorization();
            });
        var token = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            "iss", "aud", [new Claim("tenant_id", "a")], expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(Key, SecurityAlgorithms.HmacSha256)));

        var response = await host.Client.SendAsync(Get("/api/plain", header: "b", bearer: token));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync()).Should().Be("a");
        counter.Count.Should().Be(1);
    }

    // ---- Several identities ------------------------------------------------------------------

    [Fact]
    public async Task Endpoint_ShouldAnswer400_WhenTwoAuthenticatedIdentitiesNameDifferentTenants()
    {
        await using var app = await StartAsync();
        await SignInAsync(app.Host.Client, "a");

        var response = await app.Host.Client.SendAsync(Get("/api/both", header: "a", bearer: Bearer("b")));

        await AssertTenantInvalidAsync(response);
        app.Counter.Count.Should().Be(0);
    }

    [Fact]
    public async Task Endpoint_ShouldRun_WhenTwoAuthenticatedIdentitiesNameTheSameTenant()
    {
        await using var app = await StartAsync();
        await SignInAsync(app.Host.Client, "a");

        var response = await app.Host.Client.SendAsync(Get("/api/both", header: "a", bearer: Bearer("a")));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        app.Counter.Count.Should().Be(1);
    }

    // ---- Skip paths --------------------------------------------------------------------------

    [Fact]
    public async Task SkipPaths_ShouldNotBeChecked()
    {
        await using var app = await StartAsync(configure: o => o.SkipPaths.Add("/skip"));
        await SignInAsync(app.Host.Client, "a");

        var response = await app.Host.Client.SendAsync(Get("/skip/c", header: "b"));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        app.Counter.Count.Should().Be(1);
    }

    // ---- The wrapped endpoint is invisible to everything else --------------------------------

    [Fact]
    public async Task WrappedEndpoint_ShouldKeepItsPatternOrderMetadataAndDisplayName_DuringTheRequest()
    {
        await using var app = await StartAsync();

        var response = await app.Host.Client.SendAsync(Get("/api/meta", header: "a"));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = json.RootElement;
        root.GetProperty("display").GetString().Should().Be("the-original-display-name");
        root.GetProperty("pattern").GetString().Should().Be("/api/meta");
        root.GetProperty("order").GetInt32().Should().Be(7);
        root.GetProperty("marker").GetString().Should().Be("original");
        root.GetProperty("hasName").GetString().Should().Be("meta-endpoint");
    }

    [Fact]
    public async Task EndpointDataSource_ShouldBeUnchanged_AndLinkGenerationStillWorks_AfterRequestsWentThroughTheCheck()
    {
        await using var app = await StartAsync();
        await SignInAsync(app.Host.Client, "a");
        var dataSource = app.Host.Services.GetRequiredService<EndpointDataSource>();
        var before = dataSource.Endpoints.ToArray();
        var delegatesBefore = before.Select(e => e.RequestDelegate).ToArray();

        await app.Host.Client.SendAsync(Get("/api/meta", header: "a"));
        await app.Host.Client.SendAsync(Get("/api/c", header: "b"));
        await app.Host.Client.SendAsync(Get("/api/c", header: "a"));
        await app.Host.Client.SendAsync(Get("/api/mvc", header: "b"));
        var after = dataSource.Endpoints.ToArray();

        after.Should().HaveCount(before.Length);
        after.Should().BeEquivalentTo(before, options => options.Using<Endpoint>(c => c.Subject.Should().BeSameAs(c.Expectation)).WhenTypeIs<Endpoint>());
        after.Select(e => e.RequestDelegate).Should().Equal(delegatesBefore, "the data source still holds the original, unwrapped delegates");
        using var scope = app.Host.Services.CreateScope();
        var links = scope.ServiceProvider.GetRequiredService<LinkGenerator>();
        links.GetPathByName("meta-endpoint").Should().Be("/api/meta");
    }

    // ---- Routing placed after the middleware -------------------------------------------------

    [Fact]
    public async Task RoutingAfterTheMiddleware_ShouldAnswer400TenantInvalidToEveryRequestTheFirstIncluded_AndNeverRunTheEndpoint()
    {
        await using var app = await StartAsync(routingAfterMiddleware: true);

        // A bearer token for tenant a with a header naming tenant b, three times in a row: the check does not depend on
        // the order of UseRouting and UseTenantResolution, so no request is special.
        for (var i = 0; i < 3; i++)
        {
            var response = await app.Host.Client.SendAsync(Get("/api/bearer", header: "b", bearer: Bearer("a")));

            await AssertTenantInvalidAsync(response);
        }

        app.Counter.Count.Should().Be(0, "the endpoint must not run for a mismatching user, on any request");
        app.Logs.Entries.Should().NotContain(e => e.Level >= LogLevel.Critical, "the order of the middleware is no longer an error");
    }

    [Fact]
    public async Task RoutingAfterTheMiddleware_ShouldRunTheEndpoint_WhenTheCredentialsMatchTheTenantOnEveryRequest()
    {
        await using var app = await StartAsync(routingAfterMiddleware: true);

        for (var i = 0; i < 3; i++)
        {
            var response = await app.Host.Client.SendAsync(Get("/api/bearer", header: "a", bearer: Bearer("a")));

            response.StatusCode.Should().Be(HttpStatusCode.OK, $"request {i}");
            (await response.Content.ReadAsStringAsync()).Should().Be("a");
        }

        app.Counter.Count.Should().Be(3);
    }

    [Fact]
    public async Task RoutingAfterTheMiddleware_ShouldNotLetTheFirstRequestRunItsEndpointWithoutTheCheck()
    {
        await using var app = await StartAsync(routingAfterMiddleware: true);

        // A bearer token for tenant a and a header naming tenant b, as the very first request of the process.
        var first = await app.Host.Client.SendAsync(Get("/api/bearer", header: "b", bearer: Bearer("a")));

        app.Counter.Count.Should().Be(0, "a mismatching user must never reach the endpoint, even on the first request");
        first.StatusCode.Should().NotBe(HttpStatusCode.OK);
    }
}
