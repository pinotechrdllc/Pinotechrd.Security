using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using NSubstitute;
using Pinotechrd.Security.Authorization;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;
using Xunit;

namespace Pinotechrd.Security.Tests.Authorization;

public class PermissionAuthorizationHandlerCancellationTests
{
    [Fact]
    public async Task HandleRequirementAsync_ShouldPassRequestAbortedToCanAccessAsync()
    {
        using var aborted = new CancellationTokenSource();
        var http = new DefaultHttpContext { RequestAborted = aborted.Token };
        var engine = Substitute.For<ISecurityEngine>();
        engine.CanAccessAsync("MODULE", "READ", Arg.Any<CancellationToken>()).Returns(true);
        var tenant = new TenantContext();
        tenant.SetTenant("tenant-a");
        var user = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, "user-1"), new Claim("tenant_id", "tenant-a")], "Bearer"));
        var context = new AuthorizationHandlerContext([new PermissionRequirement("MODULE.READ")], user, http);

        await new PermissionAuthorizationHandler(engine, tenant, null).HandleAsync(context);

        await engine.Received(1).CanAccessAsync("MODULE", "READ", aborted.Token);
    }
}
