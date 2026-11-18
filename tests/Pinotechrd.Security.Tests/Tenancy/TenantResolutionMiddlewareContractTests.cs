using System.Security.Claims;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Xunit;

namespace Pinotechrd.Security.Tests.Tenancy;

/// <summary>
/// Tests of the documented tenant resolution contract: sources, precedence, missing-tenant behavior,
/// required path prefix, problem details, indistinguishable rejections and logging.
/// </summary>
public class TenantResolutionMiddlewareContractTests
{
    // ---- Sources and precedence -------------------------------------------------------------

    [Fact]
    public async Task Header_ShouldSetTenantAndCallNext_WhenAnonymousAndTenantIsValid()
    {
        var run = await RunAsync(headerTenant: "tenant-a", validTenants: ["tenant-a"]);

        run.NextCalled.Should().BeTrue();
        run.TenantContext.TenantId.Should().Be("tenant-a");
        run.Context.Response.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task Claim_ShouldWinOverHeader_AndStoreIsAskedOnlyAboutTheClaimTenant()
    {
        var run = await RunAsync(
            headerTenant: "tenant-b",
            user: Authenticated("tenant-a"),
            validTenants: ["tenant-a", "tenant-b"]);

        run.NextCalled.Should().BeTrue();
        run.TenantContext.TenantId.Should().Be("tenant-a");
        await run.Store.Received(1).TenantExistsAsync("tenant-a");
        await run.Store.DidNotReceive().TenantExistsAsync("tenant-b");
    }

    [Fact]
    public async Task Claim_ShouldNotFallBackToHeader_WhenTheClaimTenantIsUnknown()
    {
        var run = await RunAsync(
            headerTenant: "tenant-b",
            user: Authenticated("tenant-unknown"),
            validTenants: ["tenant-b"]);

        run.NextCalled.Should().BeFalse();
        run.Context.Response.StatusCode.Should().Be(400);
        run.TenantContext.TenantId.Should().BeNull();
        await run.Store.DidNotReceive().TenantExistsAsync("tenant-b");
    }

    // Documented behavior (README: "An authenticated principal without the claim falls through to the header").
    // Risk: a validly signed token that lacks tenant_id lets its holder choose any existing tenant through the header.
    [Fact]
    public async Task Header_ShouldBeUsed_WhenUserIsAuthenticatedButHasNoTenantClaim()
    {
        var run = await RunAsync(
            headerTenant: "tenant-b",
            user: Authenticated(tenantClaim: null),
            validTenants: ["tenant-b"]);

        run.NextCalled.Should().BeTrue();
        run.TenantContext.TenantId.Should().Be("tenant-b");
    }

    [Fact]
    public async Task Claim_ShouldBeIgnored_WhenThePrincipalIsNotAuthenticated()
    {
        var unauthenticated = new ClaimsPrincipal(new ClaimsIdentity([new Claim("tenant_id", "tenant-a")]));

        var run = await RunAsync(user: unauthenticated, validTenants: ["tenant-a"]);

        run.NextCalled.Should().BeFalse();
        run.Context.Response.StatusCode.Should().Be(400);
        await run.Store.DidNotReceiveWithAnyArgs().TenantExistsAsync(default!);
    }

    [Fact]
    public async Task SourcesClaim_ShouldRejectHeaderOnlyRequestAsTenantRequired()
    {
        var run = await RunAsync(
            new TenantResolutionOptions { Sources = TenantSources.Claim },
            headerTenant: "tenant-a",
            validTenants: ["tenant-a"],
            withProblemDetails: true);

        run.NextCalled.Should().BeFalse();
        run.Context.Response.StatusCode.Should().Be(400);
        run.Json!.RootElement.GetProperty("code").GetString().Should().Be("tenant_required");
        await run.Store.DidNotReceiveWithAnyArgs().TenantExistsAsync(default!);
    }

    [Fact]
    public async Task SourcesClaim_ShouldStillResolveFromTheClaim()
    {
        var run = await RunAsync(
            new TenantResolutionOptions { Sources = TenantSources.Claim },
            user: Authenticated("tenant-a"),
            validTenants: ["tenant-a"]);

        run.NextCalled.Should().BeTrue();
        run.TenantContext.TenantId.Should().Be("tenant-a");
    }

    [Fact]
    public async Task SourcesHeader_ShouldIgnoreTheClaimAndUseTheHeader()
    {
        var run = await RunAsync(
            new TenantResolutionOptions { Sources = TenantSources.Header },
            headerTenant: "tenant-b",
            user: Authenticated("tenant-a"),
            validTenants: ["tenant-a", "tenant-b"]);

        run.NextCalled.Should().BeTrue();
        run.TenantContext.TenantId.Should().Be("tenant-b");
        await run.Store.DidNotReceive().TenantExistsAsync("tenant-a");
    }

    [Fact]
    public async Task SourcesNone_ShouldTreatEveryRequestAsHavingNoTenant()
    {
        var run = await RunAsync(
            new TenantResolutionOptions { Sources = TenantSources.None },
            headerTenant: "tenant-a",
            user: Authenticated("tenant-a"),
            validTenants: ["tenant-a"]);

        run.NextCalled.Should().BeFalse();
        run.Context.Response.StatusCode.Should().Be(400);
        await run.Store.DidNotReceiveWithAnyArgs().TenantExistsAsync(default!);
    }

    [Fact]
    public async Task Header_ShouldUseTheConfiguredHeaderName()
    {
        var options = new TenantResolutionOptions { HeaderName = "X-Org" };
        var run = await RunAsync(options, customHeaders: new() { ["X-Org"] = "tenant-a" }, validTenants: ["tenant-a"]);

        run.TenantContext.TenantId.Should().Be("tenant-a");
    }

    [Fact]
    public async Task Header_ShouldUseTheFirstValue_WhenSeveralAreSent()
    {
        var context = NewContext("/api/x");
        context.Request.Headers["TenantId"] = new Microsoft.Extensions.Primitives.StringValues(["tenant-a", "tenant-b"]);

        var run = await RunAsync(context: context, validTenants: ["tenant-a", "tenant-b"]);

        run.TenantContext.TenantId.Should().Be("tenant-a");
        await run.Store.DidNotReceive().TenantExistsAsync("tenant-b");
    }

    // ---- Missing tenant behavior ------------------------------------------------------------

    [Fact]
    public async Task Continue_ShouldCallNextWithoutTenant_WhenNoTenantOnApiPath()
    {
        var run = await RunAsync(new TenantResolutionOptions { OnMissingTenant = MissingTenantBehavior.Continue });

        run.NextCalled.Should().BeTrue();
        run.TenantContext.TenantId.Should().BeNull();
        run.Context.Response.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task Continue_ShouldStillRejectAnUnknownTenant()
    {
        var run = await RunAsync(
            new TenantResolutionOptions { OnMissingTenant = MissingTenantBehavior.Continue },
            headerTenant: "tenant-unknown",
            withProblemDetails: true);

        run.NextCalled.Should().BeFalse();
        run.Context.Response.StatusCode.Should().Be(400);
        run.Json!.RootElement.GetProperty("code").GetString().Should().Be("tenant_invalid");
    }

    [Fact]
    public async Task Reject_ShouldReturn400AndNotCallNext_WhenNoTenantOnApiPath()
    {
        var run = await RunAsync();

        run.NextCalled.Should().BeFalse();
        run.Context.Response.StatusCode.Should().Be(400);
        run.TenantContext.TenantId.Should().BeNull();
    }

    // ---- RequiredPathPrefix -----------------------------------------------------------------

    [Fact]
    public async Task RequiredPathPrefix_ShouldBlockOnlyPathsUnderTheConfiguredPrefix()
    {
        var options = new TenantResolutionOptions { RequiredPathPrefix = "/v1" };

        var outside = await RunAsync(options, path: "/api/x");
        var inside = await RunAsync(options, path: "/v1/x");

        outside.NextCalled.Should().BeTrue();
        outside.Context.Response.StatusCode.Should().Be(200);
        inside.NextCalled.Should().BeFalse();
        inside.Context.Response.StatusCode.Should().Be(400);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task RequiredPathPrefix_ShouldNeverBlockAMissingTenant_WhenNullOrEmpty(string? prefix)
    {
        var options = new TenantResolutionOptions { RequiredPathPrefix = prefix };

        foreach (var path in new[] { "/api/x", "/v1/x", "/" })
        {
            var run = await RunAsync(options, path: path);
            run.NextCalled.Should().BeTrue($"path {path} requires no tenant");
            run.Context.Response.StatusCode.Should().Be(200);
        }
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/api/x")]
    [InlineData("/anything/else")]
    [InlineData("/health")]
    public async Task RequiredPathPrefix_ShouldBlockEveryPath_WhenSlash(string path)
    {
        var run = await RunAsync(new TenantResolutionOptions { RequiredPathPrefix = "/" }, path: path);

        run.NextCalled.Should().BeFalse();
        run.Context.Response.StatusCode.Should().Be(400);
    }

    [Fact]
    public async Task RequiredPathPrefix_ShouldNotBlockPathsOutsideTheDefaultPrefix()
    {
        var run = await RunAsync(path: "/health");

        run.NextCalled.Should().BeTrue();
    }

    [Fact]
    public async Task RequiredPathPrefix_ShouldMatchCaseInsensitively()
    {
        var run = await RunAsync(path: "/API/Orders");

        run.NextCalled.Should().BeFalse();
        run.Context.Response.StatusCode.Should().Be(400);
    }

    // Characterization (probe): the prefix is a plain string prefix with no segment boundary, as documented
    // ("path starts with this prefix"). "/apix" is therefore treated as under "/api". Report to the reviewer.
    [Fact]
    public async Task RequiredPathPrefix_ShouldMatchAsPlainStringPrefix_WithoutSegmentBoundary()
    {
        var run = await RunAsync(path: "/apix/foo");

        run.Context.Response.StatusCode.Should().Be(400);
    }

    // ---- SkipPaths --------------------------------------------------------------------------

    [Fact]
    public async Task SkipPaths_ShouldBypassResolutionEvenWithAnInvalidTenantHeader()
    {
        var options = new TenantResolutionOptions { RequiredPathPrefix = "/" };
        options.SkipPaths.Add("/health");

        var run = await RunAsync(options, path: "/HEALTH/live", headerTenant: "tenant-unknown");

        run.NextCalled.Should().BeTrue();
        run.TenantContext.TenantId.Should().BeNull();
        run.Context.Response.StatusCode.Should().Be(200);
        await run.Store.DidNotReceiveWithAnyArgs().TenantExistsAsync(default!);
    }

    [Fact]
    public async Task SkipPaths_ShouldNotBypassOtherPaths()
    {
        var options = new TenantResolutionOptions();
        options.SkipPaths.Add("/health");

        var run = await RunAsync(options, path: "/api/x");

        run.NextCalled.Should().BeFalse();
        run.Context.Response.StatusCode.Should().Be(400);
    }

    // ---- Problem details --------------------------------------------------------------------

    [Fact]
    public async Task ProblemDetails_ShouldDescribeMissingTenant_WhenServiceIsRegistered()
    {
        var run = await RunAsync(withProblemDetails: true);

        run.Context.Response.StatusCode.Should().Be(400);
        run.Context.Response.ContentType.Should().StartWith("application/problem+json");
        run.Json!.RootElement.GetProperty("status").GetInt32().Should().Be(400);
        run.Json.RootElement.GetProperty("code").GetString().Should().Be("tenant_required");
    }

    [Fact]
    public async Task ProblemDetails_ShouldDescribeUnknownTenant_WhenServiceIsRegistered()
    {
        var run = await RunAsync(headerTenant: "tenant-unknown", withProblemDetails: true);

        run.Context.Response.StatusCode.Should().Be(400);
        run.Context.Response.ContentType.Should().StartWith("application/problem+json");
        run.Json!.RootElement.GetProperty("status").GetInt32().Should().Be(400);
        run.Json.RootElement.GetProperty("code").GetString().Should().Be("tenant_invalid");
    }

    [Fact]
    public async Task PlainText_ShouldBeWritten_WhenNoProblemDetailsServiceIsRegistered()
    {
        var missing = await RunAsync();
        var unknown = await RunAsync(headerTenant: "tenant-unknown");

        missing.Context.Response.StatusCode.Should().Be(400);
        missing.Body.Should().Be("TenantId is required.");
        unknown.Context.Response.StatusCode.Should().Be(400);
        unknown.Body.Should().Be("Invalid TenantId.");
        (missing.Context.Response.ContentType ?? string.Empty).Should().NotStartWith("application/problem+json");
    }

    [Fact]
    public async Task PlainText_ShouldUseTheConfiguredHeaderName()
    {
        var run = await RunAsync(new TenantResolutionOptions { HeaderName = "X-Org" });

        run.Body.Should().Be("X-Org is required.");
    }

    // ---- Unknown tenants are indistinguishable ---------------------------------------------

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnknownTenants_ShouldGetIdenticalStatusHeadersAndBody(bool withProblemDetails)
    {
        var first = await RunAsync(headerTenant: "tenant-unknown-1", withProblemDetails: withProblemDetails);
        var second = await RunAsync(headerTenant: "tenant-other-2", withProblemDetails: withProblemDetails);

        second.Context.Response.StatusCode.Should().Be(first.Context.Response.StatusCode);
        if (withProblemDetails)
        {
            // traceId is per request by design; every other member must match.
            StableMembers(second).Should().Equal(StableMembers(first));
        }
        else
        {
            second.RawBody.Should().Equal(first.RawBody);
        }
        HeadersOf(second).Should().Equal(HeadersOf(first));
    }

    [Fact]
    public async Task ExistingButUnknownLookingTenant_ShouldNotLeakThroughTheResponse_ComparedToMissing()
    {
        // A missing tenant and an unknown tenant must be different codes, but an unknown tenant must not echo its value.
        var run = await RunAsync(headerTenant: "secret-tenant-value", withProblemDetails: true);

        run.Body.Should().NotContain("secret-tenant-value");
    }

    // ---- Logging ----------------------------------------------------------------------------

    [Theory]
    [InlineData("valid")]
    [InlineData("unknown")]
    [InlineData("missing")]
    [InlineData("claim")]
    public async Task Logs_ShouldNeverContainTheTenantValue_AtInformationOrAbove(string outcome)
    {
        var logger = new CapturingLogger<TenantResolutionMiddleware>();
        const string secret = "sup3r-s3cret-tenant";
        var run = outcome switch
        {
            "valid" => await RunAsync(headerTenant: secret, validTenants: [secret], logger: logger),
            "unknown" => await RunAsync(headerTenant: secret, logger: logger),
            "claim" => await RunAsync(user: Authenticated(secret), validTenants: [secret], logger: logger),
            _ => await RunAsync(logger: logger)
        };

        run.Context.Should().NotBeNull();
        logger.Entries.Where(e => e.Level >= LogLevel.Information && e.Text.Contains(secret)).Should().BeEmpty();
        // Stronger than required: the README says tenant ids are never logged at all.
        logger.Entries.Where(e => e.Text.Contains(secret)).Should().BeEmpty();
    }

    // ---- Hostile header values --------------------------------------------------------------

    public static TheoryData<string> HostileValues() =>
    [
        new string('a', 100_000),
        "tenant\r\nSet-Cookie: x=1",
        "tenant\0null",
        "a'; DROP TABLE Tenants;--",
        "' OR '1'='1",
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "tenant/../other",
        "ténänt-中文-\U0001F600",
        "‮evil",
        "<script>alert(1)</script>",
        "   "
    ];

    [Theory]
    [MemberData(nameof(HostileValues))]
    public async Task HostileHeaderValues_ShouldBeRejectedWithoutThrowingOrBeingEchoed(string hostile)
    {
        foreach (var withProblemDetails in new[] { false, true })
        {
            var run = await RunAsync(headerTenant: hostile, withProblemDetails: withProblemDetails);

            run.NextCalled.Should().BeFalse();
            run.Context.Response.StatusCode.Should().Be(400);
            run.TenantContext.TenantId.Should().BeNull();
            if (hostile.Trim().Length > 0)
            {
                run.Body.Should().NotContain(hostile);
            }
            foreach (var header in run.Context.Response.Headers)
            {
                header.Value.ToString().Should().NotContain(hostile.Trim().Length == 0 ? "\u0001" : hostile);
            }
        }
    }

    [Fact]
    public async Task HostileHeaderValues_ShouldNotBeLogged()
    {
        var logger = new CapturingLogger<TenantResolutionMiddleware>();
        const string hostile = "a'; DROP TABLE Tenants;--";

        await RunAsync(headerTenant: hostile, logger: logger);

        logger.Entries.Where(e => e.Text.Contains("DROP TABLE")).Should().BeEmpty();
    }

    // ---- Support ----------------------------------------------------------------------------

    private sealed record Run(
        HttpContext Context,
        TenantContext TenantContext,
        ITenantStore Store,
        bool NextCalled,
        byte[] RawBody)
    {
        public string Body => Encoding.UTF8.GetString(RawBody);

        public JsonDocument? Json => RawBody.Length == 0 ? null : JsonDocument.Parse(RawBody);
    }

    private static DefaultHttpContext NewContext(string path)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static ClaimsPrincipal Authenticated(string? tenantClaim)
    {
        var claims = new List<Claim> { new("sub", "user-1") };
        if (tenantClaim != null) claims.Add(new Claim("tenant_id", tenantClaim));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType: "Bearer"));
    }

    private static async Task<Run> RunAsync(
        TenantResolutionOptions? options = null,
        string path = "/api/x",
        string? headerTenant = null,
        Dictionary<string, string>? customHeaders = null,
        ClaimsPrincipal? user = null,
        string[]? validTenants = null,
        bool withProblemDetails = false,
        ILogger<TenantResolutionMiddleware>? logger = null,
        DefaultHttpContext? context = null)
    {
        context ??= NewContext(path);
        if (headerTenant != null) context.Request.Headers["TenantId"] = headerTenant;
        if (customHeaders != null)
        {
            foreach (var (key, value) in customHeaders) context.Request.Headers[key] = value;
        }
        if (user != null) context.User = user;

        var services = new ServiceCollection();
        if (withProblemDetails) services.AddLogging().AddProblemDetails();
        context.RequestServices = services.BuildServiceProvider();

        var nextCalled = false;
        var middleware = new TenantResolutionMiddleware(
            _ => { nextCalled = true; return Task.CompletedTask; },
            options ?? new TenantResolutionOptions(),
            logger ?? Substitute.For<ILogger<TenantResolutionMiddleware>>());

        var store = Substitute.For<ITenantStore>();
        store.TenantExistsAsync(Arg.Any<string>()).Returns(false);
        foreach (var tenant in validTenants ?? [])
        {
            store.TenantExistsAsync(tenant).Returns(true);
        }

        var tenantContext = new TenantContext();
        await middleware.InvokeAsync(context, tenantContext, store);

        var body = ((MemoryStream)context.Response.Body).ToArray();
        return new Run(context, tenantContext, store, nextCalled, body);
    }

    private static string[] StableMembers(Run run) =>
        run.Json!.RootElement.EnumerateObject()
            .Where(p => p.Name != "traceId")
            .Select(p => $"{p.Name}={p.Value.GetRawText()}")
            .ToArray();

    private static string[] HeadersOf(Run run) =>
        run.Context.Response.Headers
            .OrderBy(h => h.Key, StringComparer.Ordinal)
            .Select(h => $"{h.Key}={h.Value}")
            .ToArray();

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, string Text)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var text = formatter(state, exception);
            if (state is IEnumerable<KeyValuePair<string, object?>> pairs)
            {
                text += " " + string.Join(" ", pairs.Select(p => $"{p.Key}={p.Value}"));
            }
            Entries.Add((logLevel, text + (exception?.ToString() ?? string.Empty)));
        }
    }
}
