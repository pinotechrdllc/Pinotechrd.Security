using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
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
/// <c>CacheOutputPerTenant()</c> and <c>TenantOutputCachePolicy</c>: cached output is keyed by the tenant the middleware resolved,
/// and is switched off when that tenant cannot be trusted (resolution has not run, or a tenant-required path has none).
/// Every endpoint answers "tenant#n", where n counts executions, so a cached response is recognisable by a repeated body.
/// </summary>
public class TenantOutputCacheTests
{
    private static readonly SymmetricSecurityKey Key = new("output-cache-signing-key-32-bytes!!!!"u8.ToArray());

    private static readonly AuthorizeAttribute BearerOnly = new() { AuthenticationSchemes = "Bearer" };

    private sealed class NoopHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public NoopHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync() => Task.FromResult(AuthenticateResult.NoResult());
    }

    /// <summary>Counts executions of one endpoint and renders "tenant#n".</summary>
    private sealed class Probe
    {
        private int _count;

        public int Count => Volatile.Read(ref _count);

        public IResult Handle(TenantContext tenant) => Results.Text($"{tenant.TenantId ?? "none"}#{Interlocked.Increment(ref _count)}");
    }

    private static string Bearer(string tenant)
    {
        var token = new JwtSecurityToken(
            claims: [new Claim("tenant_id", tenant), new Claim("sub", "user-1")],
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(Key, SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static Task<InProcessHost> StartAsync(
        Action<WebApplication> pipeline,
        Action<TenantResolutionOptions>? configure = null)
    {
        var options = new TenantResolutionOptions();
        configure?.Invoke(options);
        return InProcessHost.StartAsync(
            builder =>
            {
                var services = builder.Services;
                services.AddScoped<TenantContext>();
                services.AddSingleton(options);
                services.AddSingleton<ITenantStore>(new FixedTenantStore("a", "b"));
                services.AddProblemDetails();
                services.AddOutputCache();
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
            pipeline);
    }

    /// <summary>The documented order: authentication, tenant resolution, routing, authorization, output cache.</summary>
    private static void DocumentedOrder(WebApplication app, Action<WebApplication> endpoints)
    {
        app.UseAuthentication();
        app.UseTenantResolution();
        app.UseRouting();
        app.UseAuthorization();
        app.UseOutputCache();
        endpoints(app);
    }

    private static HttpRequestMessage Get(string path, string? tenant = null, string? bearer = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (tenant != null) request.Headers.Add("TenantId", tenant);
        if (bearer != null) request.Headers.Authorization = new("Bearer", bearer);
        return request;
    }

    private static async Task<string> BodyAsync(HttpClient client, HttpRequestMessage request)
    {
        var response = await client.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return await response.Content.ReadAsStringAsync();
    }

    // ---- One entry per resolved tenant -------------------------------------------------------

    [Fact]
    public async Task CacheOutputPerTenant_ShouldCacheEachTenantSeparately_ForTheSamePath()
    {
        var probe = new Probe();
        await using var host = await StartAsync(app => DocumentedOrder(app, a => a.MapGet("/api/catalog", probe.Handle).CacheOutputPerTenant()));

        var a1 = await BodyAsync(host.Client, Get("/api/catalog", "a"));
        var a2 = await BodyAsync(host.Client, Get("/api/catalog", "a"));
        var b1 = await BodyAsync(host.Client, Get("/api/catalog", "b"));
        var b2 = await BodyAsync(host.Client, Get("/api/catalog", "b"));
        var a3 = await BodyAsync(host.Client, Get("/api/catalog", "a"));

        a1.Should().Be("a#1");
        a2.Should().Be("a#1", "the second request of tenant a is served from its cache entry");
        b1.Should().Be("b#2", "tenant b must not be served the entry of tenant a");
        b2.Should().Be("b#2");
        a3.Should().Be("a#1", "tenant b's entry did not replace tenant a's");
        probe.Count.Should().Be(2, "one execution per tenant");
    }

    [Fact]
    public async Task CacheOutputPerTenant_ShouldKeepTheQueryStringPartOfTheKey()
    {
        var probe = new Probe();
        await using var host = await StartAsync(app => DocumentedOrder(app, a => a.MapGet("/api/catalog", probe.Handle).CacheOutputPerTenant()));

        var first = await BodyAsync(host.Client, Get("/api/catalog?page=1", "a"));
        var second = await BodyAsync(host.Client, Get("/api/catalog?page=2", "a"));
        var again = await BodyAsync(host.Client, Get("/api/catalog?page=1", "a"));

        first.Should().Be("a#1");
        second.Should().Be("a#2", "the default policy still varies by query");
        again.Should().Be("a#1");
    }

    [Fact]
    public async Task CacheOutputPerTenant_ShouldWorkOnAGroup()
    {
        var probe = new Probe();
        await using var host = await StartAsync(app => DocumentedOrder(app, a =>
        {
            var group = a.MapGroup("/api").CacheOutputPerTenant();
            group.MapGet("/catalog", probe.Handle);
        }));

        (await BodyAsync(host.Client, Get("/api/catalog", "a"))).Should().Be("a#1");
        (await BodyAsync(host.Client, Get("/api/catalog", "b"))).Should().Be("b#2");
        (await BodyAsync(host.Client, Get("/api/catalog", "a"))).Should().Be("a#1");
    }

    [Fact]
    public async Task CacheOutputPerTenant_ShouldApplyTheCallersSettings_SuchAsExpiry()
    {
        var probe = new Probe();
        await using var host = await StartAsync(app => DocumentedOrder(app, a =>
            a.MapGet("/api/catalog", probe.Handle).CacheOutputPerTenant(policy => policy.Expire(TimeSpan.FromMilliseconds(300)))));

        (await BodyAsync(host.Client, Get("/api/catalog", "a"))).Should().Be("a#1");
        (await BodyAsync(host.Client, Get("/api/catalog", "a"))).Should().Be("a#1");
        await Task.Delay(1200);

        (await BodyAsync(host.Client, Get("/api/catalog", "a"))).Should().Be("a#2", "the entry expired after the configured time");
    }

    // ---- The key is the resolved tenant, not the raw header ----------------------------------

    [Fact]
    public async Task CacheKey_ShouldBeTheResolvedTenant_WhenTheRequestCarriesTwoHeaderValues()
    {
        var probe = new Probe();
        await using var host = await StartAsync(app => DocumentedOrder(app, a => a.MapGet("/api/catalog", probe.Handle).CacheOutputPerTenant()));
        (await BodyAsync(host.Client, Get("/api/catalog", "a"))).Should().Be("a#1");

        // Two TenantId lines on the wire (HttpClient would fold them into one "a, b" value). The resolver uses the first line;
        // the second one must neither create nor select an entry.
        var first = await RawGetAsync(host, "/api/catalog", "TenantId: a", "TenantId: b");
        var second = await RawGetAsync(host, "/api/catalog", "TenantId: b", "TenantId: a");

        first.Should().Be("a#1", "the resolved tenant is a, so the request shares tenant a's entry");
        second.Should().Be("b#2", "the resolved tenant is b: it must not be served tenant a's entry");
    }

    private const string CrLf = "\r\n";

    /// <summary>Sends a GET with the given raw header lines over a plain socket and returns the response body.</summary>
    private static async Task<string> RawGetAsync(InProcessHost host, string path, params string[] headerLines)
    {
        using var tcp = new System.Net.Sockets.TcpClient();
        await tcp.ConnectAsync(host.Client.BaseAddress!.Host, host.Client.BaseAddress.Port);
        var stream = tcp.GetStream();
        var request = $"GET {path} HTTP/1.1{CrLf}Host: {host.Client.BaseAddress!.Authority}{CrLf}{string.Join(CrLf, headerLines)}{CrLf}Connection: close{CrLf}{CrLf}";
        await stream.WriteAsync(System.Text.Encoding.ASCII.GetBytes(request));
        using var reader = new StreamReader(stream, System.Text.Encoding.ASCII);
        var response = await reader.ReadToEndAsync();
        response.Should().StartWith("HTTP/1.1 200", "the raw request was accepted");
        var body = response[(response.IndexOf(CrLf + CrLf, StringComparison.Ordinal) + 4)..];
        // Chunked bodies are framed by hex sizes; the payload is the line that holds "tenant#n".
        return body.Split(CrLf).Single(line => line.Contains('#'));
    }

    [Theory]
    [InlineData("A")]
    [InlineData("a b")]
    [InlineData("a,b")]
    [InlineData("a/../b")]
    [InlineData("-a")]
    [InlineData("tenant-unknown")]
    [InlineData("a\u0000")]
    public async Task CacheKey_ShouldNotBeCreatedOrHit_WhenTheResolverRejectsTheHeader(string header)
    {
        var probe = new Probe();
        await using var host = await StartAsync(app => DocumentedOrder(app, a => a.MapGet("/api/catalog", probe.Handle).CacheOutputPerTenant()));
        (await BodyAsync(host.Client, Get("/api/catalog", "a"))).Should().Be("a#1");

        HttpResponseMessage rejected;
        try
        {
            rejected = await host.Client.SendAsync(Get("/api/catalog", header));
        }
        catch (Exception ex) when (ex is HttpRequestException or FormatException or InvalidOperationException)
        {
            // The client itself refused to send a header value that is not valid HTTP: nothing reached the server.
            return;
        }

        rejected.StatusCode.Should().Be(HttpStatusCode.BadRequest, "the middleware rejects an id it does not accept before the cache sees the request");
        probe.Count.Should().Be(1, "no execution, no new entry");
        (await BodyAsync(host.Client, Get("/api/catalog", "a"))).Should().Be("a#1", "tenant a's entry is untouched");
        (await BodyAsync(host.Client, Get("/api/catalog", "b"))).Should().Be("b#2", "no entry was stored under the rejected header's value for tenant b to hit");
    }

    [Fact]
    public async Task CacheKey_ShouldNotServeACachedTenantResponse_WhenTheHeaderIsMissingOnARequiredPath()
    {
        var probe = new Probe();
        await using var host = await StartAsync(app => DocumentedOrder(app, a => a.MapGet("/api/catalog", probe.Handle).CacheOutputPerTenant()));
        (await BodyAsync(host.Client, Get("/api/catalog", "a"))).Should().Be("a#1");

        var response = await host.Client.SendAsync(Get("/api/catalog"));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        probe.Count.Should().Be(1);
    }

    // ---- Caching switched off ----------------------------------------------------------------

    [Fact]
    public async Task OutputCacheBeforeAuthorization_ShouldCacheNothing_BecauseTheUserIsNotFinalYet()
    {
        var probe = new Probe();
        await using var host = await StartAsync(app =>
        {
            app.UseAuthentication();
            app.UseTenantResolution();
            app.UseRouting();
            app.UseOutputCache();
            app.UseAuthorization();
            app.MapGet("/api/catalog", probe.Handle).CacheOutputPerTenant();
        });

        (await BodyAsync(host.Client, Get("/api/catalog", "a"))).Should().Be("a#1");
        (await BodyAsync(host.Client, Get("/api/catalog", "a"))).Should().Be("a#2", "the authorization middleware has not run, so nothing is cached");
    }

    [Fact]
    public async Task OutputCacheAfterAuthorization_ShouldCachePerTenant()
    {
        var probe = new Probe();
        await using var host = await StartAsync(app => DocumentedOrder(app, a => a.MapGet("/api/catalog", probe.Handle).CacheOutputPerTenant()));

        (await BodyAsync(host.Client, Get("/api/catalog", "a"))).Should().Be("a#1");
        (await BodyAsync(host.Client, Get("/api/catalog", "a"))).Should().Be("a#1");
        (await BodyAsync(host.Client, Get("/api/catalog", "b"))).Should().Be("b#2");
    }

    [Fact]
    public async Task OutputCacheBeforeTheTenantMiddleware_ShouldCacheNothing_WithTheTenantPolicy()
    {
        var probe = new Probe();
        await using var host = await StartAsync(app =>
        {
            app.UseAuthentication();
            app.UseRouting();
            app.UseOutputCache();
            app.UseTenantResolution();
            app.UseAuthorization();
            app.MapGet("/api/catalog", probe.Handle).CacheOutputPerTenant();
        });

        var a1 = await BodyAsync(host.Client, Get("/api/catalog", "a"));
        var a2 = await BodyAsync(host.Client, Get("/api/catalog", "a"));
        var b1 = await BodyAsync(host.Client, Get("/api/catalog", "b"));

        a1.Should().Be("a#1");
        a2.Should().Be("a#2", "nothing may be cached when the policy cannot see the resolved tenant");
        b1.Should().Be("b#3");
    }

    [Fact]
    public async Task OutputCacheBeforeTheTenantMiddleware_ShouldCacheAcrossTenants_WithAPlainCacheOutput_AsTheContrast()
    {
        var probe = new Probe();
        await using var host = await StartAsync(app =>
        {
            app.UseAuthentication();
            app.UseRouting();
            app.UseOutputCache();
            app.UseTenantResolution();
            app.UseAuthorization();
            app.MapGet("/api/catalog", probe.Handle).CacheOutput();
        });

        var a = await BodyAsync(host.Client, Get("/api/catalog", "a"));
        var b = await BodyAsync(host.Client, Get("/api/catalog", "b"));

        a.Should().Be("a#1");
        b.Should().Be("a#1", "this is the leak CacheOutputPerTenant exists to prevent: tenant b receives tenant a's response");
    }

    [Fact]
    public async Task PlainCacheOutput_ShouldServeOneTenantsResponseToAnother_AsTheDocumentedContrast()
    {
        var probe = new Probe();
        await using var host = await StartAsync(app => DocumentedOrder(app, a => a.MapGet("/api/catalog", probe.Handle).CacheOutput()));

        var a = await BodyAsync(host.Client, Get("/api/catalog", "a"));
        var b = await BodyAsync(host.Client, Get("/api/catalog", "b"));

        a.Should().Be("a#1");
        b.Should().Be("a#1", "a cache keyed only by path and query hands tenant a's response to tenant b");
        probe.Count.Should().Be(1);
    }

    [Fact]
    public async Task TenantRequiredPathWithNoTenant_ShouldCacheNothing_WhenTheMiddlewareLetsTheRequestThrough()
    {
        var probe = new Probe();
        await using var host = await StartAsync(
            app => DocumentedOrder(app, a => a.MapGet("/api/catalog", probe.Handle).CacheOutputPerTenant()),
            o => o.OnMissingTenant = MissingTenantBehavior.Continue);

        var first = await BodyAsync(host.Client, Get("/api/catalog"));
        var second = await BodyAsync(host.Client, Get("/api/catalog"));
        var tenant = await BodyAsync(host.Client, Get("/api/catalog", "a"));

        first.Should().Be("none#1");
        second.Should().Be("none#2", "a tenant-required path without a tenant is never cached");
        tenant.Should().Be("a#3");
    }

    [Fact]
    public async Task PathThatDoesNotRequireATenant_ShouldBeCachedUnderItsOwnKey_AndNeverSharedWithARealTenant()
    {
        var probe = new Probe();
        await using var host = await StartAsync(app => DocumentedOrder(app, a => a.MapGet("/public/catalog", probe.Handle).CacheOutputPerTenant()));

        var anonymous1 = await BodyAsync(host.Client, Get("/public/catalog"));
        var anonymous2 = await BodyAsync(host.Client, Get("/public/catalog"));
        var tenantA = await BodyAsync(host.Client, Get("/public/catalog", "a"));
        var anonymous3 = await BodyAsync(host.Client, Get("/public/catalog"));

        anonymous1.Should().Be("none#1");
        anonymous2.Should().Be("none#1", "no tenant is expected on this path, so the entry for 'no tenant' may be shared");
        tenantA.Should().Be("a#2", "a real tenant never gets the entry that was stored for 'no tenant'");
        anonymous3.Should().Be("none#1");
    }

    [Fact]
    public async Task SkipPath_ShouldCacheNothing_BecauseTenantResolutionDidNotRunThere()
    {
        var probe = new Probe();
        await using var host = await StartAsync(
            app => DocumentedOrder(app, a => a.MapGet("/health/info", probe.Handle).CacheOutputPerTenant()),
            o => o.SkipPaths.Add("/health"));

        var first = await BodyAsync(host.Client, Get("/health/info", "a"));
        var second = await BodyAsync(host.Client, Get("/health/info", "a"));

        first.Should().Be("none#1", "tenant resolution is skipped on this path, so the header is not honoured");
        second.Should().Be("none#2", "without a resolved tenant nothing is cached");
    }

    [Fact]
    public async Task AuthenticatedRequests_ShouldNotBeCached_ByTheDefaultPolicy()
    {
        var probe = new Probe();
        await using var host = await StartAsync(app => DocumentedOrder(app, a =>
            a.MapGet("/api/me", probe.Handle).RequireAuthorization(BearerOnly).CacheOutputPerTenant()));
        var token = Bearer("a");

        var first = await BodyAsync(host.Client, Get("/api/me", "a", token));
        var second = await BodyAsync(host.Client, Get("/api/me", "a", token));

        first.Should().Be("a#1");
        second.Should().Be("a#2", "a response built for an authenticated user is not stored");
    }

    [Fact]
    public async Task ARequestWithAnAuthorizationHeader_ShouldNeitherFillNorUseTheAnonymousEntry()
    {
        var probe = new Probe();
        await using var host = await StartAsync(app => DocumentedOrder(app, a => a.MapGet("/api/catalog", probe.Handle).CacheOutputPerTenant()));

        var withToken = await BodyAsync(host.Client, Get("/api/catalog", "a", Bearer("a")));
        var anonymous = await BodyAsync(host.Client, Get("/api/catalog", "a"));
        var anonymousAgain = await BodyAsync(host.Client, Get("/api/catalog", "a"));

        withToken.Should().Be("a#1");
        anonymous.Should().Be("a#2", "the response built for the request with a credential was not stored");
        anonymousAgain.Should().Be("a#2");
    }

    [Fact]
    public async Task NonGetRequests_ShouldNotBeCached_ByTheDefaultPolicy()
    {
        var probe = new Probe();
        await using var host = await StartAsync(app => DocumentedOrder(app, a => a.MapPost("/api/catalog", probe.Handle).CacheOutputPerTenant()));

        async Task<string> PostAsync()
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/api/catalog");
            request.Headers.Add("TenantId", "a");
            return await BodyAsync(host.Client, request);
        }

        (await PostAsync()).Should().Be("a#1");
        (await PostAsync()).Should().Be("a#2");
    }
}
