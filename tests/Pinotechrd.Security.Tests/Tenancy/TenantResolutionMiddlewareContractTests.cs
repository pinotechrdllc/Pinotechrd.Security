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

    // README: an authenticated user without the claim is rejected on a path that requires a tenant, and the header is
    // never read for it. This closes the tenant-hopping risk of letting a claim-less token pick its tenant.
    [Theory]
    [InlineData(null, MissingTenantBehavior.Reject, TenantSources.Claim | TenantSources.Header)]
    [InlineData(null, MissingTenantBehavior.Continue, TenantSources.Claim | TenantSources.Header)]
    [InlineData("", MissingTenantBehavior.Reject, TenantSources.Claim | TenantSources.Header)]
    [InlineData("", MissingTenantBehavior.Continue, TenantSources.Claim | TenantSources.Header)]
    [InlineData(null, MissingTenantBehavior.Reject, TenantSources.Header)]
    [InlineData(null, MissingTenantBehavior.Continue, TenantSources.Header)]
    [InlineData(null, MissingTenantBehavior.Reject, TenantSources.Claim)]
    [InlineData(null, MissingTenantBehavior.Continue, TenantSources.Claim)]
    [InlineData(null, MissingTenantBehavior.Reject, TenantSources.None)]
    [InlineData(null, MissingTenantBehavior.Continue, TenantSources.None)]
    public async Task AuthenticatedWithoutTheClaim_ShouldBeRejectedAsTenantInvalid_OnARequiredPath(
        string? claim, MissingTenantBehavior onMissing, TenantSources sources)
    {
        var run = await RunAsync(
            new TenantResolutionOptions { OnMissingTenant = onMissing, Sources = sources },
            headerTenant: "tenant-b",
            user: Authenticated(claim),
            validTenants: ["tenant-b"],
            withProblemDetails: true);

        run.NextCalled.Should().BeFalse();
        run.Context.Response.StatusCode.Should().Be(400);
        run.Json!.RootElement.GetProperty("code").GetString().Should().Be("tenant_invalid");
        run.TenantContext.TenantId.Should().BeNull();
        await run.Store.DidNotReceiveWithAnyArgs().TenantExistsAsync(default!);
    }

    [Theory]
    [InlineData(null, MissingTenantBehavior.Reject)]
    [InlineData(null, MissingTenantBehavior.Continue)]
    [InlineData("", MissingTenantBehavior.Reject)]
    public async Task AuthenticatedWithoutTheClaim_ShouldContinueWithoutTenantAndIgnoreTheHeader_OnANonRequiredPath(
        string? claim, MissingTenantBehavior onMissing)
    {
        var run = await RunAsync(
            new TenantResolutionOptions { OnMissingTenant = onMissing },
            path: "/health",
            headerTenant: "tenant-b",
            user: Authenticated(claim),
            validTenants: ["tenant-b"]);

        run.NextCalled.Should().BeTrue();
        run.TenantContext.TenantId.Should().BeNull();
        await run.Store.DidNotReceiveWithAnyArgs().TenantExistsAsync(default!);
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
    public async Task SourcesHeader_ShouldBehaveLikeTheDefault_ClaimWinsAndTheHeaderIsNeverAsked()
    {
        var run = await RunAsync(
            new TenantResolutionOptions { Sources = TenantSources.Header },
            headerTenant: "tenant-b",
            user: Authenticated("tenant-a"),
            validTenants: ["tenant-a", "tenant-b"]);

        run.NextCalled.Should().BeTrue();
        run.TenantContext.TenantId.Should().Be("tenant-a");
        await run.Store.DidNotReceive().TenantExistsAsync("tenant-b");
    }

    [Fact]
    public async Task SourcesHeader_ShouldStillResolveAnonymousRequestsFromTheHeader()
    {
        var run = await RunAsync(
            new TenantResolutionOptions { Sources = TenantSources.Header },
            headerTenant: "tenant-b",
            validTenants: ["tenant-b"]);

        run.TenantContext.TenantId.Should().Be("tenant-b");
    }

    [Theory]
    [InlineData(TenantSources.None)]
    [InlineData(TenantSources.Claim)]
    public async Task AnonymousRequests_ShouldIgnoreTheHeader_WhenTheHeaderSourceIsOff(TenantSources sources)
    {
        var run = await RunAsync(
            new TenantResolutionOptions { Sources = sources },
            headerTenant: "tenant-a",
            validTenants: ["tenant-a"],
            withProblemDetails: true);

        run.NextCalled.Should().BeFalse();
        run.Context.Response.StatusCode.Should().Be(400);
        run.Json!.RootElement.GetProperty("code").GetString().Should().Be("tenant_required");
        await run.Store.DidNotReceiveWithAnyArgs().TenantExistsAsync(default!);
    }

    [Fact]
    public async Task SourcesNone_ShouldStillUseTheClaimOfAnAuthenticatedUser()
    {
        // The claim cannot be turned off (README): Sources only decides what anonymous requests may use.
        var run = await RunAsync(
            new TenantResolutionOptions { Sources = TenantSources.None },
            headerTenant: "tenant-b",
            user: Authenticated("tenant-a"),
            validTenants: ["tenant-a", "tenant-b"]);

        run.NextCalled.Should().BeTrue();
        run.TenantContext.TenantId.Should().Be("tenant-a");
        await run.Store.DidNotReceive().TenantExistsAsync("tenant-b");
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

    // README: matching is by whole path segments, so "/apix" and "/api-v2" are outside "/api".
    [Theory]
    [InlineData("/api")]
    [InlineData("/API/x")]
    [InlineData("/api/")]
    [InlineData("/api/orders/1")]
    public async Task RequiredPathPrefix_ShouldMatchTheSegmentAndItsChildren(string path)
    {
        var run = await RunAsync(path: path);

        run.NextCalled.Should().BeFalse();
        run.Context.Response.StatusCode.Should().Be(400);
    }

    [Theory]
    [InlineData("/apix")]
    [InlineData("/apix/foo")]
    [InlineData("/api-v2")]
    [InlineData("/api-v2/foo")]
    [InlineData("/apis/x")]
    public async Task RequiredPathPrefix_ShouldNotMatchAPathThatOnlySharesTheLeadingCharacters(string path)
    {
        var run = await RunAsync(path: path);

        run.NextCalled.Should().BeTrue();
        run.Context.Response.StatusCode.Should().Be(200);
    }

    [Theory]
    [InlineData("api")]
    [InlineData("/api")]
    [InlineData("/api/")]
    [InlineData("api/")]
    public async Task RequiredPathPrefix_ShouldWorkWithOrWithoutALeadingOrTrailingSlash(string prefix)
    {
        var options = new TenantResolutionOptions { RequiredPathPrefix = prefix };

        (await RunAsync(options, path: "/api/x")).Context.Response.StatusCode.Should().Be(400);
        (await RunAsync(options, path: "/apix")).NextCalled.Should().BeTrue();
    }

    [Theory]
    [InlineData("/health", "/health/live", true)]
    [InlineData("/health", "/health", true)]
    [InlineData("/health", "/HEALTH/live", true)]
    [InlineData("/health", "/healthcheck-x", false)]
    [InlineData("/health", "/healthy", false)]
    [InlineData("/api/auth", "/api/auth/login", true)]
    [InlineData("/api/auth", "/api/authors", false)]
    [InlineData("api/auth", "/api/auth/login", true)]
    [InlineData("api/auth", "/api/authors", false)]
    public async Task SkipPaths_ShouldMatchWholeSegmentsOnly(string skip, string path, bool skipped)
    {
        var options = new TenantResolutionOptions { RequiredPathPrefix = "/" };
        options.SkipPaths.Add(skip);

        var run = await RunAsync(options, path: path);

        run.NextCalled.Should().Be(skipped);
        run.Context.Response.StatusCode.Should().Be(skipped ? 200 : 400);
    }

    // Probes (A3): what the matcher does with encoded and doubled separators. The middleware compares the path as
    // the server gives it (Kestrel has already decoded it), so these pin the current behavior.
    [Fact]
    public async Task Probe_APercentEncodedSegmentIsNotDecodedByTheMiddleware_SoItIsOutsideTheRequiredPrefix()
    {
        var context = NewContext("/");
        context.Request.Path = new PathString("/%61pi/x");

        var run = await RunAsync(context: context);

        run.NextCalled.Should().BeTrue();
    }

    [Fact]
    public async Task Probe_ADoubleSlashAfterThePrefixStillMatches()
    {
        var run = await RunAsync(path: "/api//x");

        run.Context.Response.StatusCode.Should().Be(400);
    }

    [Fact]
    public async Task Probe_ADoubleSlashBeforeThePrefixDoesNotMatch()
    {
        var run = await RunAsync(path: "//api/x");

        run.NextCalled.Should().BeTrue();
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

    // ---- Tenant id format (A4/B6) -----------------------------------------------------------

    public static TheoryData<string> MalformedTenantIds() =>
    [
        new string('a', 57),
        "Tenant-A",
        "ABC",
        "a_b",
        "a b",
        "a.b",
        "a/b",
        "tenant-é",
        "ab",
        "-abc"
    ];

    [Theory]
    [MemberData(nameof(MalformedTenantIds))]
    public async Task MalformedHeaderTenantId_ShouldBeRejectedAsInvalidWithoutAskingTheStore(string id)
    {
        var run = await RunAsync(headerTenant: id, validTenants: [id], withProblemDetails: true);

        run.NextCalled.Should().BeFalse();
        run.Context.Response.StatusCode.Should().Be(400);
        run.Json!.RootElement.GetProperty("code").GetString().Should().Be("tenant_invalid");
        await run.Store.DidNotReceiveWithAnyArgs().TenantExistsAsync(default!);
    }

    [Theory]
    [MemberData(nameof(MalformedTenantIds))]
    public async Task MalformedClaimTenantId_ShouldBeRejectedAsInvalidWithoutAskingTheStore(string id)
    {
        var run = await RunAsync(user: Authenticated(id), validTenants: [id], withProblemDetails: true);

        run.NextCalled.Should().BeFalse();
        run.Context.Response.StatusCode.Should().Be(400);
        run.Json!.RootElement.GetProperty("code").GetString().Should().Be("tenant_invalid");
        await run.Store.DidNotReceiveWithAnyArgs().TenantExistsAsync(default!);
    }

    [Fact]
    public async Task TenantId_ShouldBeAccepted_At56Characters_AndRejectedAt57()
    {
        var ok = new string('a', 56);
        var tooLong = new string('a', 57);

        var accepted = await RunAsync(headerTenant: ok, validTenants: [ok]);
        var rejected = await RunAsync(headerTenant: tooLong, validTenants: [tooLong]);

        accepted.NextCalled.Should().BeTrue();
        accepted.TenantContext.TenantId.Should().Be(ok);
        rejected.NextCalled.Should().BeFalse();
        rejected.Context.Response.StatusCode.Should().Be(400);
    }

    [Fact]
    public async Task LowerCaseGuidTenantId_ShouldBeAccepted()
    {
        const string guid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

        var run = await RunAsync(headerTenant: guid, validTenants: [guid]);

        run.TenantContext.TenantId.Should().Be(guid);
    }

    // ---- Credentials and several identities --------------------------------------------------

    [Theory]
    [InlineData(MissingTenantBehavior.Reject)]
    [InlineData(MissingTenantBehavior.Continue)]
    public async Task AuthorizationHeader_ShouldNotStopTheTenantHeader_WhenNobodyIsAuthenticated(MissingTenantBehavior onMissing)
    {
        var context = NewContext("/api/x");
        context.Request.Headers["Authorization"] = "Bearer something";

        var run = await RunAsync(
            new TenantResolutionOptions { OnMissingTenant = onMissing },
            headerTenant: "tenant-b",
            validTenants: ["tenant-b"],
            context: context);

        run.NextCalled.Should().BeTrue();
        run.TenantContext.TenantId.Should().Be("tenant-b");
        run.Context.Response.StatusCode.Should().Be(200);
    }

    [Theory]
    [InlineData("Basic dXNlcjpwYXNz")]
    [InlineData("Negotiate abc")]
    [InlineData("Bearer expired.token.value")]
    [InlineData("")]
    public async Task AnyAuthorizationHeaderValue_ShouldLeaveTheTenantHeaderInForce(string value)
    {
        var context = NewContext("/api/x");
        context.Request.Headers["Authorization"] = value;

        var run = await RunAsync(headerTenant: "tenant-b", validTenants: ["tenant-b"], context: context);

        run.TenantContext.TenantId.Should().Be("tenant-b");
        await run.Store.Received(1).TenantExistsAsync("tenant-b");
    }

    [Fact]
    public async Task AuthorizationHeader_ShouldNotChangeAnAuthenticatedRequest_WhichStillUsesItsClaim()
    {
        var context = NewContext("/api/x");
        context.Request.Headers["Authorization"] = "Bearer something";

        var run = await RunAsync(
            headerTenant: "tenant-b",
            user: Authenticated("tenant-a"),
            validTenants: ["tenant-a", "tenant-b"],
            context: context);

        run.TenantContext.TenantId.Should().Be("tenant-a");
        await run.Store.DidNotReceive().TenantExistsAsync("tenant-b");
    }

    [Fact]
    public async Task SecondIdentity_ShouldProvideTheClaim_WhenOnlyItIsAuthenticated_AndTheHeaderIsNeverRead()
    {
        var unauthenticated = new ClaimsIdentity([new Claim("sub", "someone")]);
        var authenticated = new ClaimsIdentity([new Claim("tenant_id", "tenant-a")], "Bearer");

        var run = await RunAsync(
            headerTenant: "tenant-b",
            user: new ClaimsPrincipal([unauthenticated, authenticated]),
            validTenants: ["tenant-a", "tenant-b"]);

        run.NextCalled.Should().BeTrue();
        run.TenantContext.TenantId.Should().Be("tenant-a");
        await run.Store.DidNotReceive().TenantExistsAsync("tenant-b");
    }

    // The claim must come from an authenticated identity: an unauthenticated identity that happens to carry a
    // tenant_id claim must not decide the tenant (the permission handler already ignores such identities).
    [Fact]
    public async Task SecondIdentity_ShouldUseTheAuthenticatedIdentitysClaim_NotTheClaimOfAnUnauthenticatedFirstIdentity()
    {
        var unauthenticated = new ClaimsIdentity([new Claim("tenant_id", "tenant-evil")]);
        var authenticated = new ClaimsIdentity([new Claim("tenant_id", "tenant-a")], "Bearer");

        var run = await RunAsync(
            user: new ClaimsPrincipal([unauthenticated, authenticated]),
            validTenants: ["tenant-a", "tenant-evil"]);

        run.TenantContext.TenantId.Should().Be("tenant-a");
        await run.Store.DidNotReceive().TenantExistsAsync("tenant-evil");
    }

    [Fact]
    public async Task UnauthenticatedIdentityWithAClaim_ShouldNeverProvideTheTenant_WhenNoIdentityIsAuthenticated()
    {
        var unauthenticated = new ClaimsIdentity([new Claim("tenant_id", "tenant-a")]);

        var run = await RunAsync(user: new ClaimsPrincipal(unauthenticated), validTenants: ["tenant-a"]);

        run.TenantContext.TenantId.Should().BeNull();
    }

    [Fact]
    public async Task TwoAuthenticatedIdentitiesWithDifferentTenants_ShouldBeRejectedAsTenantInvalid()
    {
        var first = new ClaimsIdentity([new Claim("tenant_id", "tenant-a")], "Bearer");
        var second = new ClaimsIdentity([new Claim("tenant_id", "tenant-b")], "Cookie");

        var run = await RunAsync(
            headerTenant: "tenant-a",
            user: new ClaimsPrincipal([first, second]),
            validTenants: ["tenant-a", "tenant-b"],
            withProblemDetails: true);

        run.NextCalled.Should().BeFalse();
        run.Context.Response.StatusCode.Should().Be(400);
        run.Json!.RootElement.GetProperty("code").GetString().Should().Be("tenant_invalid");
        run.TenantContext.TenantId.Should().BeNull();
        await run.Store.DidNotReceiveWithAnyArgs().TenantExistsAsync(default!);
    }

    [Fact]
    public async Task TwoAuthenticatedIdentitiesWithTheSameTenant_ShouldResolveThatTenant()
    {
        var first = new ClaimsIdentity([new Claim("tenant_id", "tenant-a")], "Bearer");
        var second = new ClaimsIdentity([new Claim("tenant_id", "tenant-a")], "Cookie");

        var run = await RunAsync(user: new ClaimsPrincipal([first, second]), validTenants: ["tenant-a"]);

        run.NextCalled.Should().BeTrue();
        run.TenantContext.TenantId.Should().Be("tenant-a");
    }

    [Fact]
    public async Task OneIdentityWithTwoDifferentTenantClaims_ShouldBeRejected()
    {
        var identity = new ClaimsIdentity([new Claim("tenant_id", "tenant-a"), new Claim("tenant_id", "tenant-b")], "Bearer");

        var run = await RunAsync(user: new ClaimsPrincipal(identity), validTenants: ["tenant-a", "tenant-b"]);

        run.NextCalled.Should().BeFalse();
        run.Context.Response.StatusCode.Should().Be(400);
    }

    [Fact]
    public async Task ClaimOnAnUnauthenticatedIdentity_ShouldBeIgnored_SoTheHeaderIsUsed()
    {
        var unauthenticated = new ClaimsIdentity([new Claim("tenant_id", "tenant-a")]);

        var run = await RunAsync(
            headerTenant: "tenant-b",
            user: new ClaimsPrincipal(unauthenticated),
            validTenants: ["tenant-a", "tenant-b"]);

        run.TenantContext.TenantId.Should().Be("tenant-b");
        await run.Store.DidNotReceive().TenantExistsAsync("tenant-a");
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
