using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
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

/// <summary>
/// The tenant consistency check is installed through the request's endpoint feature, so it applies to every endpoint a request
/// runs, whatever the order of <c>UseRouting</c> and <c>UseTenantResolution</c>, and also to endpoints that are chosen again
/// later in the same request (exception handler, status code pages) and to <c>MapFallback</c>.
/// The authenticated user comes from a non-default Bearer scheme that only the endpoint's authorization requirement triggers,
/// which is the case the check exists for: the middleware resolves the tenant from the header, and only afterwards does the
/// user's claim become known.
/// </summary>
public class TenantConsistencyEndpointFeatureTests
{
    private static readonly SymmetricSecurityKey Key = new("endpoint-feature-signing-key-32-bytes!!"u8.ToArray());

    private sealed class NoopHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public NoopHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync() => Task.FromResult(AuthenticateResult.NoResult());
    }

    private sealed class Logs : ILoggerProvider
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public ILogger CreateLogger(string categoryName) => new Capture(this);

        public void Dispose()
        {
        }

        private sealed class Capture(Logs owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                lock (owner.Entries) owner.Entries.Add((logLevel, formatter(state, exception)));
            }
        }
    }

    private sealed record Started(InProcessHost Host, ExecutionCounter Counter, ExecutionCounter ErrorCounter, Logs Logs) : IAsyncDisposable
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

    private static readonly AuthorizeAttribute BearerOnly = new() { AuthenticationSchemes = "Bearer" };

    private static async Task<Started> StartAsync(Action<WebApplication, ExecutionCounter, ExecutionCounter> pipeline)
    {
        var counter = new ExecutionCounter();
        var errorCounter = new ExecutionCounter();
        var logs = new Logs();

        var host = await InProcessHost.StartAsync(
            builder =>
            {
                var services = builder.Services;
                builder.Logging.AddProvider(logs);
                services.AddScoped<TenantContext>();
                services.AddSingleton(new TenantResolutionOptions());
                services.AddSingleton<ITenantStore>(new FixedTenantStore("a", "b"));
                services.AddProblemDetails();
                services.AddAuthentication("Anon")
                    .AddScheme<AuthenticationSchemeOptions, NoopHandler>("Anon", null)
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
            app => pipeline(app, counter, errorCounter));

        return new Started(host, counter, errorCounter, logs);
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

    /// <summary>The usual pipeline except that routing is placed after the tenant middleware.</summary>
    private static void RoutingAfterTenantResolution(WebApplication app, ExecutionCounter counter, ExecutionCounter _)
    {
        app.UseAuthentication();
        app.UseTenantResolution();
        app.UseRouting();
        app.UseAuthorization();
        app.MapGet("/api/bearer", (TenantContext t) => { counter.Hit(); return Results.Text(t.TenantId ?? "none"); })
            .RequireAuthorization(BearerOnly);
    }

    // ---- UseRouting after UseTenantResolution, many concurrent first requests ----------------

    [Fact]
    public async Task ConcurrentFirstRequests_ShouldAllAnswer400TenantInvalid_AndNeverRunTheEndpoint_WhenRoutingComesAfterTheMiddleware()
    {
        await using var app = await StartAsync(RoutingAfterTenantResolution);
        var token = Bearer("a");

        var responses = await Task.WhenAll(Enumerable.Range(0, 40).Select(_ => app.Host.Client.SendAsync(Get("/api/bearer", header: "b", bearer: token))));

        foreach (var response in responses) await AssertTenantInvalidAsync(response);
        app.Counter.Count.Should().Be(0, "no request may reach the endpoint, not even the first ones that race to wrap it");
    }

    [Fact]
    public async Task ConcurrentFirstRequests_ShouldGiveEachRequestItsOwnAnswer_WhenMatchingAndMismatchingOnesRace()
    {
        await using var app = await StartAsync(RoutingAfterTenantResolution);
        var token = Bearer("a");

        var results = await Task.WhenAll(Enumerable.Range(0, 40).Select(async i =>
        {
            var matching = i % 2 == 0;
            var response = await app.Host.Client.SendAsync(Get("/api/bearer", header: matching ? "a" : "b", bearer: token));
            return (matching, response);
        }));

        foreach (var (matching, response) in results)
        {
            if (matching)
            {
                response.StatusCode.Should().Be(HttpStatusCode.OK);
                (await response.Content.ReadAsStringAsync()).Should().Be("a");
            }
            else
            {
                await AssertTenantInvalidAsync(response);
            }
        }

        app.Counter.Count.Should().Be(20, "exactly the matching requests ran the endpoint");
    }

    [Fact]
    public async Task MatchingRequest_ShouldAnswer200_WhenRoutingComesAfterTheMiddleware()
    {
        await using var app = await StartAsync(RoutingAfterTenantResolution);

        var response = await app.Host.Client.SendAsync(Get("/api/bearer", header: "a", bearer: Bearer("a")));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync()).Should().Be("a");
        app.Counter.Count.Should().Be(1);
        app.Logs.Entries.Should().NotContain(e => e.Level >= LogLevel.Critical);
    }

    // ---- Endpoints chosen again during the request -------------------------------------------

    [Fact]
    public async Task ExceptionHandlerReExecution_ShouldCheckTheErrorEndpoint_AndNotRunItForAMismatchingUser()
    {
        await using var app = await StartAsync((web, counter, errorCounter) =>
        {
            web.UseAuthentication();
            web.UseTenantResolution();
            web.UseExceptionHandler("/error");
            web.UseRouting();
            web.UseAuthorization();
            web.MapGet("/api/boom", () => { counter.Hit(); throw new InvalidOperationException("boom"); }).AllowAnonymous();
            web.MapGet("/error", () => { errorCounter.Hit(); return Results.Text("handled"); }).RequireAuthorization(BearerOnly);
        });

        // The failing endpoint is anonymous, so nobody is authenticated there. The error endpoint asks for the Bearer scheme,
        // which authenticates tenant a while the tenant resolved from the header is b.
        var response = await app.Host.Client.SendAsync(Get("/api/boom", header: "b", bearer: Bearer("a")));

        await AssertTenantInvalidAsync(response);
        app.Counter.Count.Should().Be(1, "the original endpoint ran and threw");
        app.ErrorCounter.Count.Should().Be(0, "the re-executed error endpoint must be checked too");
    }

    [Fact]
    public async Task ExceptionHandlerReExecution_ShouldRunTheErrorEndpoint_WhenTheUserMatchesTheTenant()
    {
        await using var app = await StartAsync((web, counter, errorCounter) =>
        {
            web.UseAuthentication();
            web.UseTenantResolution();
            web.UseExceptionHandler("/error");
            web.UseRouting();
            web.UseAuthorization();
            web.MapGet("/api/boom", () => { counter.Hit(); throw new InvalidOperationException("boom"); }).AllowAnonymous();
            web.MapGet("/error", () => { errorCounter.Hit(); return Results.Text("handled"); }).RequireAuthorization(BearerOnly);
        });

        var response = await app.Host.Client.SendAsync(Get("/api/boom", header: "a", bearer: Bearer("a")));

        (await response.Content.ReadAsStringAsync()).Should().Be("handled");
        app.ErrorCounter.Count.Should().Be(1);
    }

    [Fact]
    public async Task StatusCodePagesReExecution_ShouldCheckThePageEndpoint_AndNotRunItForAMismatchingUser()
    {
        await using var app = await StartAsync((web, counter, errorCounter) =>
        {
            web.UseAuthentication();
            web.UseTenantResolution();
            web.UseStatusCodePagesWithReExecute("/status/{0}");
            web.UseRouting();
            web.UseAuthorization();
            web.MapGet("/api/missing", () => { counter.Hit(); return Results.NotFound(); }).AllowAnonymous();
            web.MapGet("/status/{code}", (string code) => { errorCounter.Hit(); return Results.Text("page " + code); }).RequireAuthorization(BearerOnly);
        });

        var response = await app.Host.Client.SendAsync(Get("/api/missing", header: "b", bearer: Bearer("a")));

        await AssertTenantInvalidAsync(response);
        app.ErrorCounter.Count.Should().Be(0, "the re-executed status page must be checked too");
    }

    [Fact]
    public async Task StatusCodePagesReExecution_ShouldRunThePageEndpoint_WhenTheUserMatchesTheTenant()
    {
        await using var app = await StartAsync((web, counter, errorCounter) =>
        {
            web.UseAuthentication();
            web.UseTenantResolution();
            web.UseStatusCodePagesWithReExecute("/status/{0}");
            web.UseRouting();
            web.UseAuthorization();
            web.MapGet("/api/missing", () => { counter.Hit(); return Results.NotFound(); }).AllowAnonymous();
            web.MapGet("/status/{code}", (string code) => { errorCounter.Hit(); return Results.Text("page " + code); }).RequireAuthorization(BearerOnly);
        });

        var response = await app.Host.Client.SendAsync(Get("/api/missing", header: "a", bearer: Bearer("a")));

        (await response.Content.ReadAsStringAsync()).Should().Be("page 404");
        app.ErrorCounter.Count.Should().Be(1);
    }

    // ---- MapFallback -------------------------------------------------------------------------

    [Fact]
    public async Task MapFallback_ShouldAnswer400_AndNotRun_WhenTheUserDiffersFromTheTenant()
    {
        await using var app = await StartAsync((web, counter, _) =>
        {
            web.UseAuthentication();
            web.UseTenantResolution();
            web.UseRouting();
            web.UseAuthorization();
            web.MapFallback(() => { counter.Hit(); return Results.Text("fallback"); }).RequireAuthorization(BearerOnly);
        });

        var response = await app.Host.Client.SendAsync(Get("/api/anything/at/all", header: "b", bearer: Bearer("a")));

        await AssertTenantInvalidAsync(response);
        app.Counter.Count.Should().Be(0);
    }

    [Fact]
    public async Task MapFallback_ShouldRun_WhenTheUserMatchesTheTenant()
    {
        await using var app = await StartAsync((web, counter, _) =>
        {
            web.UseAuthentication();
            web.UseTenantResolution();
            web.UseRouting();
            web.UseAuthorization();
            web.MapFallback(() => { counter.Hit(); return Results.Text("fallback"); }).RequireAuthorization(BearerOnly);
        });

        var response = await app.Host.Client.SendAsync(Get("/api/anything/at/all", header: "a", bearer: Bearer("a")));

        (await response.Content.ReadAsStringAsync()).Should().Be("fallback");
        app.Counter.Count.Should().Be(1);
    }

    [Fact]
    public async Task MapFallback_ShouldBeCheckedOnEveryRequest_WhenRoutingComesAfterTheMiddleware()
    {
        await using var app = await StartAsync((web, counter, _) =>
        {
            web.UseAuthentication();
            web.UseTenantResolution();
            web.UseRouting();
            web.UseAuthorization();
            web.MapFallback(() => { counter.Hit(); return Results.Text("fallback"); }).RequireAuthorization(BearerOnly);
        });
        var token = Bearer("a");

        var responses = await Task.WhenAll(Enumerable.Range(0, 10).Select(i => app.Host.Client.SendAsync(Get($"/api/x/{i}", header: "b", bearer: token))));

        foreach (var response in responses) await AssertTenantInvalidAsync(response);
        app.Counter.Count.Should().Be(0);
    }

    // ---- The wrapper is invisible and idempotent ---------------------------------------------

    [Fact]
    public async Task WrappingTheSameEndpointAgain_ShouldGiveTheSameEndpointInstance_AcrossSetsAndRequests()
    {
        var seen = new System.Collections.Concurrent.ConcurrentQueue<(int Before, int After, string? Name, string? Pattern, int? Order, string? Marker)>();
        await using var app = await StartAsync((web, counter, _) =>
        {
            web.UseAuthentication();
            web.UseTenantResolution();
            web.UseRouting();
            web.Use(async (context, next) =>
            {
                var endpoint = context.GetEndpoint();
                if (endpoint != null)
                {
                    // Something sets the endpoint it already has (middleware that saves and restores it does exactly this).
                    context.SetEndpoint(endpoint);
                    var route = context.GetEndpoint() as RouteEndpoint;
                    seen.Enqueue((
                        System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(endpoint),
                        System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(context.GetEndpoint()),
                        context.GetEndpoint()!.DisplayName,
                        route?.RoutePattern.RawText,
                        route?.Order,
                        context.GetEndpoint()!.Metadata.GetMetadata<MarkerMetadata>()?.Value));
                }

                await next();
            });
            web.UseAuthorization();
            web.MapGet("/api/meta", () => { counter.Hit(); return Results.Ok(); })
                .WithDisplayName("kept-name")
                .WithMetadata(new MarkerMetadata("kept"))
                .Add(b => ((RouteEndpointBuilder)b).Order = 3);
        });

        for (var i = 0; i < 3; i++)
        {
            (await app.Host.Client.SendAsync(Get("/api/meta", header: "a"))).StatusCode.Should().Be(HttpStatusCode.OK);
        }

        seen.Should().HaveCount(3);
        seen.Select(s => s.After).Should().OnlyContain(h => h == seen.First().After, "the same endpoint instance is handed out on every request");
        seen.Should().OnlyContain(s => s.Before == s.After, "setting the endpoint it already has does not wrap it a second time");
        seen.Should().OnlyContain(s => s.Name == "kept-name" && s.Pattern == "/api/meta" && s.Order == 3 && s.Marker == "kept");
    }

    [Fact]
    public async Task ClearingTheEndpoint_ShouldLeaveNoEndpoint_AndTheRequestFallsThrough()
    {
        await using var app = await StartAsync((web, counter, _) =>
        {
            web.UseAuthentication();
            web.UseTenantResolution();
            web.UseRouting();
            web.Use(async (context, next) =>
            {
                context.SetEndpoint(null);
                await next();
            });
            web.UseAuthorization();
            web.MapGet("/api/bearer", () => { counter.Hit(); return Results.Ok(); }).RequireAuthorization(BearerOnly);
        });

        var response = await app.Host.Client.SendAsync(Get("/api/bearer", header: "a", bearer: Bearer("a")));

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        app.Counter.Count.Should().Be(0);
    }

    [Fact]
    public async Task SkipPaths_ShouldBypassTheCheckEntirely_WhenRoutingComesAfterTheMiddleware()
    {
        var counter = new ExecutionCounter();
        var options = new TenantResolutionOptions();
        options.SkipPaths.Add("/skip");
        await using var host = await InProcessHost.StartAsync(
            builder =>
            {
                builder.Services.AddScoped<TenantContext>();
                builder.Services.AddSingleton(options);
                builder.Services.AddSingleton<ITenantStore>(new FixedTenantStore("a", "b"));
                builder.Services.AddProblemDetails();
                builder.Services.AddAuthentication("Anon")
                    .AddScheme<AuthenticationSchemeOptions, NoopHandler>("Anon", null)
                    .AddJwtBearer("Bearer", o => o.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        IssuerSigningKey = Key,
                        ValidAlgorithms = [SecurityAlgorithms.HmacSha256]
                    });
                builder.Services.AddAuthorization();
            },
            web =>
            {
                web.UseAuthentication();
                web.UseTenantResolution();
                web.UseRouting();
                web.UseAuthorization();
                web.MapGet("/skip/x", () => { counter.Hit(); return Results.Ok(); }).RequireAuthorization(BearerOnly);
            });

        var response = await host.Client.SendAsync(Get("/skip/x", header: "b", bearer: Bearer("a")));

        response.StatusCode.Should().Be(HttpStatusCode.OK, "skip paths never get the check");
        counter.Count.Should().Be(1);
    }
}
