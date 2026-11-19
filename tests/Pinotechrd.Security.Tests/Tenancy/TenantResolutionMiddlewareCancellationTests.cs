using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Xunit;

namespace Pinotechrd.Security.Tests.Tenancy;

public class TenantResolutionMiddlewareCancellationTests
{
    [Fact]
    public async Task InvokeAsync_ShouldPassRequestAbortedToTenantExistsAsync()
    {
        using var aborted = new CancellationTokenSource();
        var context = new DefaultHttpContext { RequestAborted = aborted.Token };
        context.Request.Path = "/api/users";
        context.Request.Headers["TenantId"] = "tenant-a";
        var store = Substitute.For<ITenantStore>();
        store.TenantExistsAsync("tenant-a", Arg.Any<CancellationToken>()).Returns(true);
        var middleware = new TenantResolutionMiddleware(
            _ => Task.CompletedTask, new TenantResolutionOptions(), Substitute.For<ILogger<TenantResolutionMiddleware>>());

        await middleware.InvokeAsync(context, new TenantContext(), store);

        await store.Received(1).TenantExistsAsync("tenant-a", aborted.Token);
    }
}
