using System.Text;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Xunit;

namespace Pinotechrd.Security.Tests.Tenancy;

public class TenantResolutionMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_ShouldResolveTenantFromHeader_WhenValid()
    {
        var wasNextCalled = false;
        RequestDelegate next = _ =>
        {
            wasNextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = CreateMiddleware(next);

        var context = new DefaultHttpContext();
        context.Request.Path = "/api/users";
        context.Request.Headers["TenantId"] = "tenant-a";

        var tenantContext = new TenantContext();
        var tenantStore = Substitute.For<ITenantStore>();
        tenantStore.TenantExistsAsync("tenant-a").Returns(true);

        await middleware.InvokeAsync(context, tenantContext, tenantStore);

        wasNextCalled.Should().BeTrue();
        tenantContext.TenantId.Should().Be("tenant-a");
        context.Response.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task InvokeAsync_ShouldReturnBadRequest_WhenTenantHeaderMissingForApiPath()
    {
        RequestDelegate next = _ => Task.CompletedTask;

        var middleware = CreateMiddleware(next);

        var context = new DefaultHttpContext();
        context.Request.Path = "/api/orders";
        context.Response.Body = new MemoryStream();

        var tenantContext = new TenantContext();
        var tenantStore = Substitute.For<ITenantStore>();

        await middleware.InvokeAsync(context, tenantContext, tenantStore);

        context.Response.StatusCode.Should().Be(400);
        tenantContext.TenantId.Should().BeNull();
    }

    [Fact]
    public async Task InvokeAsync_ShouldResolveTenantFromQuery_WhenHeaderMissing()
    {
        var wasNextCalled = false;
        RequestDelegate next = _ =>
        {
            wasNextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = CreateMiddleware(next);

        var context = new DefaultHttpContext();
        context.Request.Path = "/api/permissions";
        context.Request.QueryString = new QueryString("?tenantId=tenant-q");

        var tenantContext = new TenantContext();
        var tenantStore = Substitute.For<ITenantStore>();
        tenantStore.TenantExistsAsync("tenant-q").Returns(true);

        await middleware.InvokeAsync(context, tenantContext, tenantStore);

        wasNextCalled.Should().BeTrue();
        tenantContext.TenantId.Should().Be("tenant-q");
    }

    [Fact]
    public async Task InvokeAsync_ShouldResolveTenantFromJsonBody_WhenConfiguredPropertyExists()
    {
        var wasNextCalled = false;
        RequestDelegate next = _ =>
        {
            wasNextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = CreateMiddleware(next);

        var context = new DefaultHttpContext();
        context.Request.Path = "/api/auth/login";
        context.Request.Method = "POST";
        context.Request.ContentType = "application/json";
        var body = "{\"tenantId\":\"tenant-body\"}";
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(body));
        context.Request.ContentLength = context.Request.Body.Length;

        var tenantContext = new TenantContext();
        var tenantStore = Substitute.For<ITenantStore>();
        tenantStore.TenantExistsAsync("tenant-body").Returns(true);

        await middleware.InvokeAsync(context, tenantContext, tenantStore);

        wasNextCalled.Should().BeTrue();
        tenantContext.TenantId.Should().Be("tenant-body");
    }

    [Fact]
    public async Task InvokeAsync_ShouldPrioritizeAuthenticatedClaimOverHeaderQueryAndBody()
    {
        var wasNextCalled = false;
        RequestDelegate next = _ =>
        {
            wasNextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = CreateMiddleware(next);

        var context = new DefaultHttpContext();
        context.Request.Path = "/api/orders";
        context.Request.Method = "POST";
        context.Request.ContentType = "application/json";
        context.Request.Headers["TenantId"] = "tenant-header";
        context.Request.QueryString = new QueryString("?tenantId=tenant-query");
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("{\"tenantId\":\"tenant-body\"}"));
        context.Request.ContentLength = context.Request.Body.Length;
        context.User = new ClaimsPrincipal(
            new ClaimsIdentity(
            [
                new Claim("tenant_id", "tenant-claim")
            ],
            authenticationType: "Bearer"));

        var tenantContext = new TenantContext();
        var tenantStore = Substitute.For<ITenantStore>();
        tenantStore.TenantExistsAsync("tenant-claim").Returns(true);

        await middleware.InvokeAsync(context, tenantContext, tenantStore);

        wasNextCalled.Should().BeTrue();
        tenantContext.TenantId.Should().Be("tenant-claim");
        await tenantStore.Received(1).TenantExistsAsync("tenant-claim");
    }

    [Fact]
    public async Task InvokeAsync_ShouldIgnoreUnauthenticatedBearerPayload()
    {
        RequestDelegate next = _ => Task.CompletedTask;

        var middleware = CreateMiddleware(next);

        var context = new DefaultHttpContext();
        context.Request.Path = "/api/secure";
        context.Response.Body = new MemoryStream();
        context.Request.Headers["Authorization"] = "Bearer eyJhbGciOiJub25lIn0.eyJ0ZW5hbnRfaWQiOiJzcG9vZi10ZW5hbnQifQ.";

        var tenantContext = new TenantContext();
        var tenantStore = Substitute.For<ITenantStore>();

        await middleware.InvokeAsync(context, tenantContext, tenantStore);

        context.Response.StatusCode.Should().Be(400);
        tenantContext.TenantId.Should().BeNull();
        await tenantStore.DidNotReceiveWithAnyArgs().TenantExistsAsync(default!);
    }

    private static TenantResolutionMiddleware CreateMiddleware(
        RequestDelegate next,
        TenantResolutionOptions? options = null)
    {
        return new TenantResolutionMiddleware(
            next,
            options ?? new TenantResolutionOptions(),
            Substitute.For<ILogger<TenantResolutionMiddleware>>());
    }
}
