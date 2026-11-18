using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Authorization;
using NSubstitute;
using Pinotechrd.Security.Authorization;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Interfaces;
using Xunit;

namespace Pinotechrd.Security.Tests.Authorization;

public class PermissionAuthorizationHandlerTests
{
    private readonly ISecurityEngine _engine = Substitute.For<ISecurityEngine>();
    private readonly PermissionAuthorizationHandler _handler;

    public PermissionAuthorizationHandlerTests()
    {
        _handler = new PermissionAuthorizationHandler(_engine);
    }

    [Fact]
    public async Task HandleRequirementAsync_ShouldSucceed_WhenEngineReturnsTrue()
    {
        // Arrange
        var userId = "user-1";
        var moduleCode = "MODULE";
        var permission = "READ";
        // Requirement format: "Module.Permission"
        var requirement = new PermissionRequirement($"{moduleCode}.{permission}");
        
        var user = new ClaimsPrincipal(new ClaimsIdentity(new[] 
        { 
            new Claim(ClaimTypes.NameIdentifier, userId) 
        }));

        var context = new AuthorizationHandlerContext(new[] { requirement }, user, null);

        _engine.CanAccessAsync(moduleCode, permission).Returns(true);

        // Act
        await _handler.HandleAsync(context);

        // Assert
        context.HasSucceeded.Should().BeTrue();
    }

    [Fact]
    public async Task HandleRequirementAsync_ShouldNotSucceed_WhenEngineReturnsFalse()
    {
        // Arrange
        var requirement = new PermissionRequirement("MOD.PERM");
        var user = new ClaimsPrincipal(new ClaimsIdentity());
        var context = new AuthorizationHandlerContext(new[] { requirement }, user, null);

        _engine.CanAccessAsync(Arg.Any<string>(), Arg.Any<string>()).Returns(false);

        // Act
        await _handler.HandleAsync(context);

        // Assert
        context.HasSucceeded.Should().BeFalse();
    }
}
